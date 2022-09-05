// Copyright 2021 Twitter, Inc.
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

#![allow(clippy::unnecessary_unwrap)]

#[macro_use]
extern crate rustcommon_logger;

// use std::time::{Duration, Instant};

use std::collections::HashMap;
use std::{fs, mem, thread};
use std::os::unix::prelude::FileExt;
use std::sync::{Arc, Mutex};

use boring::ssl::*;
use boring::x509::X509;
use clap::{App, Arg};
use mio::{Events, Poll, Token};
use mpmc::Queue;
use rand::{Rng, RngCore, SeedableRng};
use rand_distr::Alphanumeric;
use rustcommon_logger::{Level, Logger};
use rustcommon_ratelimiter::Ratelimiter;
use slab::Slab;
use std::io::Read;
use std::io::Write;
use zstd::Decoder;

use std::io::LineWriter;

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind};
use std::net::{SocketAddr, ToSocketAddrs};

use rpc_perf::*;

/// TODO(bmartin): this should be consolidated with rpc-perf
use rustcommon_heatmap::AtomicHeatmap;
use rustcommon_heatmap::AtomicU64;

// TODO(bmartin): this should be split up into a library and binary
fn main() {
    // initialize logging
    Logger::new()
        .label("rpc-replay")
        .level(Level::Info)
        .init()
        .expect("Failed to initialize logger");

    // process command line arguments
    // TODO(bmartin): consider moving to a file based config
    let matches = App::new("rpc-replay")
        .version("0.0.0")
        .author("Brian Martin <bmartin@twitter.com>")
        .about("Replay cache logs")
        .arg(
            Arg::with_name("trace")
                .long("trace")
                .value_name("FILE")
                .help("zstd compressed cache trace")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("binary-trace")
                .long("binary-trace")
                .help("indicates the trace is in the binary format")
                .takes_value(false)
                .required(false),
        )
        .arg(
            Arg::with_name("endpoint")
                .long("endpoint")
                .value_name("HOST:PORT")
                .help("server endpoint to send traffic to")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("speed")
                .long("speed")
                .value_name("FLOAT")
                .help("replay speed as a multiplier relative to realtime")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("rate")
                .long("rate")
                .value_name("INT")
                .help("replay speed in requests/s")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("poolsize")
                .long("poolsize")
                .value_name("INT")
                .help("number of connections to open from each worker")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("workers")
                .long("workers")
                .value_name("INT")
                .help("number of client worker threads")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tls-chain")
                .long("tls-chain")
                .value_name("FILE")
                .help("TLS certificate chain")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tls-key")
                .long("tls-key")
                .value_name("FILE")
                .help("TLS private key")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tls-cert")
                .long("tls-cert")
                .value_name("FILE")
                .help("TLS certificate")
                .takes_value(true),
        )
        .get_matches();

    if matches.is_present("speed") && matches.is_present("rate") {
        fatal!("invalid configuration: 'speed' and 'rate' cannot be used together");
    }

    // config value parsing and defaults
    let trace = matches.value_of("trace").unwrap();
    let endpoint = matches.value_of("endpoint").unwrap();
    let speed: Option<f64> = matches
        .value_of("speed")
        .map(|v| v.parse().expect("invalid value for 'speed'"));
    let rate: Option<usize> = matches
        .value_of("rate")
        .map(|v| v.parse().expect("invalid value for 'rate'"));
    let poolsize: usize = matches
        .value_of("poolsize")
        .unwrap_or("1")
        .parse()
        .expect("invalid value for 'poolsize'");
    let workers: usize = matches
        .value_of("workers")
        .unwrap_or("1")
        .parse()
        .expect("invalid value for 'workers'");
    let binary = matches.is_present("binary-trace");

    // configure tls connector
    let key = matches.value_of("tls-key");
    let cert = matches.value_of("tls-cert");
    let chain = matches.value_of("tls-chain");

    let tls = if key.is_some() && cert.is_some() && chain.is_some() {
        let mut builder = SslConnector::builder(SslMethod::tls_client())
            .expect("failed to initialize TLS client");
        builder.set_verify(SslVerifyMode::NONE);
        builder
            .set_certificate_file(cert.unwrap(), SslFiletype::PEM)
            .expect("failed to set TLS cert");
        let pem = std::fs::read(chain.unwrap()).expect("failed to read certificate chain");
        let chain = X509::stack_from_pem(&pem).expect("bad certificate chain");
        for cert in chain {
            builder
                .add_extra_chain_cert(cert)
                .expect("bad certificate in chain");
        }
        builder
            .set_private_key_file(key.unwrap(), SslFiletype::PEM)
            .expect("failed to set TLS key");
        let connector = builder.build();
        Some(connector)
    } else if key.is_none() && cert.is_none() && chain.is_none() {
        None
    } else {
        fatal!("incomplete TLS config");
    };

    // lookup socket address
    let sockaddr = endpoint.to_socket_addrs().unwrap().next().unwrap();

    // Create File to Write to
    let output_file = Arc::new(Mutex::new(File::create("foo.txt").unwrap()));

    // initialize work queue
    let work = Queue::with_capacity(1024 * 1024); // arbitrarily large

    let request_heatmap = Some(Arc::new(AtomicHeatmap::<u64, AtomicU64>::new(
        1_000_000,
        3,
        Duration::from_secs(60),
        Duration::from_millis(1000),
    )));

    // spawn admin
    let mut admin = Admin::for_replay(None);
    admin.set_request_heatmap(request_heatmap.clone());
    let _admin_thread = std::thread::spawn(move || admin.run());

    // spawn workers
    for worker_id in 0..workers {

        let mut worker = Worker::new(
            sockaddr,
            poolsize,
            tls.clone(),
            work.clone(),
            request_heatmap.clone(),
            worker_id,
        );
        std::thread::spawn(move || worker.run());
    }

    let controller: Box<dyn Controller> = if let Some(rate) = rate {
        Box::new(RateController::new(rate as u64, workers as u64))
    } else {
        let speed = speed.unwrap_or(1.0);
        Box::new(SpeedController::new(speed))
    };

    let mut generator = Generator::new(trace, work, binary, controller);
    generator.run()
}

pub trait Controller {
    fn delay(&mut self, ts: u64);
}

pub struct GeneratorStats {
    sent: usize,
    skip: usize,
}

impl Default for GeneratorStats {
    fn default() -> Self {
        Self { sent: 0, skip: 0 }
    }
}

pub struct RateController {
    ratelimiter: Ratelimiter,
}

impl Default for RateController {
    fn default() -> Self {
        Self::new(0, 1)
    }
}

impl RateController {
    pub fn new(rate: u64, threads: u64) -> Self {
        Self {
            ratelimiter: Ratelimiter::new(threads, 1, rate),
        }
    }
}

impl Controller for RateController {
    fn delay(&mut self, _ts: u64) {
        self.ratelimiter.wait()
    }
}

pub struct SpeedController {
    ts_sec: u64,
    next: Instant,
    speed: f64,
}

impl Default for SpeedController {
    fn default() -> Self {
        Self::new(1.0)
    }
}

impl SpeedController {
    pub fn new(speed: f64) -> Self {
        Self {
            ts_sec: 0,
            next: Instant::now(),
            speed,
        }
    }
}

impl Controller for SpeedController {
    fn delay(&mut self, ts: u64) {
        // handle new timestamp in log
        if ts > self.ts_sec {
            let mut now = Instant::now();
            // info!("ts: {} sent: {} skip: {}", ts, sent, skip);
            if self.ts_sec != 0 {
                let log_dur = Duration::from_nanos(
                    (((ts - self.ts_sec) * 1_000_000_000) as f64 / self.speed) as u64,
                );
                self.next += log_dur;
                if now > self.next {
                    warn!("falling behind... try reducing replay rate");
                }
            }
            self.ts_sec = ts;
            // delay if needed
            while now < self.next {
                std::thread::sleep(core::time::Duration::from_micros(100));
                now = Instant::now();
            }
        }
    }
}

pub struct request_data {
    ts: u64,
    // key: String,
    keysize: usize,
    vlen: usize,
    client_id: usize,
    verb: String,
    ttl: u32,
    request: Request,
}

pub struct TimeKeeper {
    sent_time: Instant,
    recv_time: Instant,
    ts: u64,
    // key: String,
    keysize: usize,
    vlen: usize,
    client_id: usize,
    verb: String,
    ttl: u32,
}

impl TimeKeeper {
    pub fn new() -> Self {

        let time_now = Instant::now();

        Self {
            sent_time:  time_now,
            recv_time:  time_now,
            ts:         0 as u64,
            // key:        "".to_string(),
            keysize:    0 as usize,
            vlen:       0 as usize,
            client_id:  0 as usize,
            verb:       "".to_string(),
            ttl:        0 as u32
        }
    }

    pub fn set(&mut self, 
        sent_time: Instant,
        ts: u64,
        // key: String,
        keysize: usize,
        vlen: usize,
        client_id: usize,
        verb: String,
        ttl: u32,
    ) {
        self.sent_time = sent_time;
        self.ts        = ts;
        self.keysize   = keysize;
        self.vlen      = vlen;
        self.client_id = client_id;
        self.verb      = verb;
        self.ttl       = ttl;
    }

    pub fn set_recv(&mut self, recv_input: Instant) {
        self.recv_time = recv_input;
    }

    pub fn get_sent(&self) -> Instant {
        return self.sent_time;
    }

    pub fn get_recv(&self) -> Instant {
        return self.sent_time;
    }

    pub fn get_ts(&self) -> u64 {
        return self.ts;
    }

    pub fn get_vlen(&self) -> usize {
        return self.vlen;
    }

    pub fn get_client_id(&self) -> usize {
        return self.client_id;
    }

    pub fn get_verb(&self) -> String {
        return self.verb.to_string();
    }

    pub fn get_keysize(&self) -> usize {
        return self.keysize;
    }

    pub fn get_ttl(&self) -> u32 {
        return self.ttl;
    }

    pub fn check_sent(&self) -> bool {
        return self.sent_time != self.recv_time;
    }
}

pub struct Generator {
    stats: GeneratorStats,
    controller: Box<dyn Controller>,
    trace: String,
    work: Queue<request_data>,
    binary: bool,
}

impl Generator {
    pub fn new(
        trace: &str,
        work: Queue<request_data>,
        binary: bool,
        controller: Box<dyn Controller>,
    ) -> Self {
        Self {
            stats: GeneratorStats::default(),
            controller,
            trace: trace.to_string(),
            work,
            binary,
        }
    }

    pub fn run(&mut self) {

        self.ascii()
        
        // if self.binary {
        //     self.binary()
        // } else {
        //     self.ascii()
        // }
    }

    fn ascii(&mut self) {
        // open files
        let zlog = File::open(&self.trace).expect("failed to open input zlog");
        let zbuf = BufReader::new(zlog);
        let log = Decoder::with_buffer(zbuf).expect("failed to init zstd decoder");
        let buf_log = BufReader::new(log);
        let mut lines = buf_log.lines();

        while let Some(Ok(line)) = lines.next() {
            let parts: Vec<&str> = line.split(',').collect();

            let ts: u64          = parts[0].parse::<u64>().expect("invalid timestamp") + 1;
            let key              = parts[1].to_string();
            let keysize: usize   = parts[2].parse().expect("failed to parse keysize");
            let vlen: usize      = parts[3].parse().expect("failed to parse vlen");
            let client_id: usize = parts[4].parse().expect("failed to parse keysize");
            let verb             = parts[5];
            let ttl: u32         = parts[6].parse().expect("failed to parse ttl");


            let mut request = match verb {
                "get" => Request::Get { key },
                "gets" => Request::Gets { key },
                "set" => Request::Set { key, vlen, ttl },
                "add" => Request::Add { key, vlen, ttl },
                "replace" => Request::Replace { key, vlen, ttl },
                "delete" => Request::Delete { key },
                _ => {
                    self.stats.skip += 1;
                    continue;
                }
            };

            let mut current_request = request_data {
                ts: ts,
                // key: key,
                keysize: keysize,
                vlen: vlen,
                client_id: client_id,
                verb: verb.to_string(),
                ttl: ttl,
                request: request,
            };

            self.controller.delay(ts);

            while let Err(r) = self.work.push(current_request) {
                current_request = r;
            }

            self.stats.sent += 1;
        }
    }
}

// A very fast PRNG
pub fn rng() -> rand_xoshiro::Xoshiro256PlusPlus {
    rand_xoshiro::Xoshiro256PlusPlus::seed_from_u64(0)
}

struct Worker {
    sessions: Slab<Session>,
    ready_queue: VecDeque<Token>,
    poll: Poll,
    work: Queue<request_data>,
    request_heatmap: Option<Arc<AtomicHeatmap<u64, AtomicU64>>>,
    rng: rand_xoshiro::Xoshiro256PlusPlus,
    time_table: HashMap<(usize, Token), TimeKeeper>,
    worker_id: usize,
}

impl Worker {
    pub fn new(
        addr: SocketAddr,
        poolsize: usize,
        tls: Option<SslConnector>,
        work: Queue<request_data>,
        request_heatmap: Option<Arc<AtomicHeatmap<u64, AtomicU64>>>,
        worker_id: usize
    ) -> Self {

        let time_table: HashMap<(usize, Token), TimeKeeper> = HashMap::new();

        let poll = mio::Poll::new().unwrap();

        let mut sessions: Slab<Session> = Slab::with_capacity(poolsize);

        let mut ready_queue: VecDeque<Token> = VecDeque::with_capacity(poolsize);

        for _ in 0..poolsize {
            let stream = TcpStream::connect(addr).expect("failed to connect");
            let mut session = if let Some(tls) = tls.as_ref() {
                match tls.connect("localhost", stream) {
                    Ok(stream) => Session::tls_with_capacity(stream, 1024, 512 * 1024),
                    Err(HandshakeError::WouldBlock(stream)) => {
                        Session::handshaking_with_capacity(stream, 1024, 512 * 1024)
                    }
                    Err(_) => {
                        panic!("tls failure");
                    }
                }
            } else {
                Session::plain_with_capacity(stream, 1024, 512 * 1024)
            };
            let entry = sessions.vacant_entry();
            let token = Token(entry.key());
            ready_queue.push_back(token);
            session.set_token(token);
            session.register(&poll).expect("register failed");
            entry.insert(session);
        }

        Self {
            sessions,
            ready_queue,
            poll,
            work,
            request_heatmap,
            rng: rng(),
            time_table,
            worker_id,
        }
    }

    pub fn send_request(&mut self, token: Token, request_struct: request_data) {
        let session = self.sessions.get_mut(token.0).expect("bad token");
        REQUEST.increment();

        let request = request_struct.request;
        let mut time_keeper = TimeKeeper::new();

        match request {
            Request::Get { key } => {
                REQUEST_GET.increment();
                let _ = session.write_all(format!("get {}\r\n", key).as_bytes());
                debug!("get {}", key);
            }
            Request::Gets { key } => {
                REQUEST_GET.increment();
                let _ = session.write_all(format!("gets {}\r\n", key).as_bytes());
                debug!("get {}", key);
            }
            Request::Set { key, vlen, ttl } => {
                let value = (&mut self.rng as &mut dyn RngCore)
                    .sample_iter(&Alphanumeric)
                    .take(vlen)
                    .collect::<Vec<u8>>();
                let _ = session.write_all(format!("set {} 0 {} {}\r\n", key, ttl, vlen).as_bytes());
                let _ = session.write_all(&value);
                let _ = session.write_all(b"\r\n");
                debug!("set {} 0 {} {}", key, ttl, vlen);
            }
            Request::Add { key, vlen, ttl } => {
                let value = (&mut self.rng as &mut dyn RngCore)
                    .sample_iter(&Alphanumeric)
                    .take(vlen)
                    .collect::<Vec<u8>>();
                let _ = session.write_all(format!("add {} 0 {} {}\r\n", key, ttl, vlen).as_bytes());
                let _ = session.write_all(&value);
                let _ = session.write_all(b"\r\n");
                debug!("add {} 0 {} {}", key, ttl, vlen);
            }
            Request::Replace { key, vlen, ttl } => {
                let value = (&mut self.rng as &mut dyn RngCore)
                    .sample_iter(&Alphanumeric)
                    .take(vlen)
                    .collect::<Vec<u8>>();
                let _ =
                    session.write_all(format!("replace {} 0 {} {}\r\n", key, ttl, vlen).as_bytes());
                let _ = session.write_all(&value);
                let _ = session.write_all(b"\r\n");
                debug!("replace {} 0 {} {}", key, ttl, vlen);
            }
            Request::Delete { key } => {
                let _ = session.write_all(format!("delete {}\r\n", key).as_bytes());
                debug!("delete {}", key);
            }
        }

        let now       = Instant::now();
        let ts        = request_struct.ts;
        let keysize   = request_struct.keysize;
        let vlen      = request_struct.vlen;
        let client_id = request_struct.client_id;
        let verb      = request_struct.verb;
        let ttl       = request_struct.ttl;

        time_keeper.set(
            now,
            ts,
            keysize,
            vlen,
            client_id,
            verb,
            ttl, 
        );

        let time_table_key = (self.worker_id, token);
        let _ = session.flush();
        self.time_table.insert(time_table_key, time_keeper);
        let _ = session.reregister(&self.poll);
    }

    pub fn run(&mut self) {

        // Type inference lets us omit an explicit type signature (which
        // would be `HashMap<String, String>` in this example).

        let mut events = Events::with_capacity(1024);
        loop {
            if let Some(token) = self.ready_queue.pop_front() {
                if let Some(request_struct) = self.work.pop() {
                    self.send_request(token, request_struct);
                } else {
                    self.ready_queue.push_front(token);
                }
            }

            let _ = self
                .poll
                .poll(&mut events, Some(std::time::Duration::from_micros(1))); // Changed to Micros for better latency accuracies

            for event in &events {
                let token = event.token();
                let session = self.sessions.get_mut(token.0).expect("unknown token");

                // handle error events first
                if event.is_error() {
                    let _ = session.deregister(&self.poll);
                    session.close();
                    warn!("error");
                }

                // handle handshaking
                if session.is_handshaking() {
                    if let Err(e) = session.do_handshake() {
                        if e.kind() != ErrorKind::WouldBlock {
                            let _ = session.deregister(&self.poll);
                            session.close();
                            warn!("error");
                        }
                    }
                    if session.is_handshaking() {
                        let _ = session.reregister(&self.poll);
                        continue;
                    }
                }

                // handle reads
                if event.is_readable() {
                    match session.fill_buf().map(|b| b.len()) {
                        Ok(0) => {
                            let _ = session.deregister(&self.poll);
                            session.close();
                            warn!("server hangup");
                        }
                        Ok(_) => match decode(session) {
                            Ok(_) => {

                                RESPONSE.increment();

                                let time_table_key = (self.worker_id, token);

                                let recv_time       = Instant::now();
                                let matching_req    = self.time_table.get(&time_table_key).expect("REASON");
                                let sent_time       = matching_req.get_sent();
                                let time_difference = format!("{:?}\n", recv_time - sent_time);

                                let ts        = matching_req.get_ts();
                                let keysize   = matching_req.get_keysize();
                                let vlen      = matching_req.get_vlen();
                                let client_id = matching_req.get_client_id();
                                let verb      = matching_req.get_verb();
                                let ttl       = matching_req.get_ttl();
                                let latency   = time_difference.split_whitespace().nth(3).unwrap().to_owned();
    
                                println!("--latency_stats: {} {} {} {} {}", verb, vlen, ttl, client_id, latency);

                                if let Some(ref heatmap) = self.request_heatmap {
                                    let now = Instant::now();
                                    let elapsed = now - session.timestamp();
                                    let us = (elapsed.as_secs_f64() * 1_000_000.0) as u64;
                                    heatmap.increment(now, us, 1);
                                }

                                if let Some(request_struct) = self.work.pop() {
                                    self.send_request(token, request_struct);
                                } else {
                                    self.time_table.remove(&time_table_key);
                                    self.ready_queue.push_back(token);
                                }

                                continue;
                            }
                            Err(ParseError::Incomplete) => {
                                continue;
                            }
                            Err(_) => {
                                let _ = session.deregister(&self.poll);
                                session.close();
                                warn!("parse error");
                            }
                        },
                        Err(e) => {
                            let _ = session.deregister(&self.poll);
                            session.close();
                            warn!("read error: {}", e);
                        }
                    }
                }

                // handle writes
                if event.is_writable() && session.write_pending() > 0 {
                    session.flush().expect("flush failed");
                    if session.write_pending() > 0 {
                        let _ = session.reregister(&self.poll);
                    }
                }
            }
        }
    }
}

pub enum Request {
    Get { key: String },
    Gets { key: String },
    Set { key: String, vlen: usize, ttl: u32 },
    Add { key: String, vlen: usize, ttl: u32 },
    Replace { key: String, vlen: usize, ttl: u32 },
    Delete { key: String },
}

#[derive(Clone, Debug, PartialEq)]
pub enum ParseError {
    Incomplete,
    Error,
    Unknown,
}

// this is a very barebones memcache parser
fn decode(buffer: &mut Session) -> Result<(), ParseError> {
    // no-copy borrow as a slice
    let buf: &[u8] = (*buffer).buffer();

    debug!("buffer content: {:?}", buf);

    for response in &[
        "STORED\r\n",
        "NOT_STORED\r\n",
        "EXISTS\r\n",
        "NOT_FOUND\r\n",
        "DELETED\r\n",
        "TOUCHED\r\n",
    ] {
        let bytes = response.as_bytes();
        if buf.len() >= bytes.len() && &buf[0..bytes.len()] == bytes {
            let _ = buffer.consume(bytes.len());
            return Ok(());
        }
    }

    let mut windows = buf.windows(5);
    if let Some(response_end) = windows.position(|w| w == b"END\r\n") {
        if response_end > 0 {
            RESPONSE_HIT.increment();
        }
        let _ = buffer.consume(response_end + 5);
        return Ok(());
    }

    Err(ParseError::Incomplete)
}
