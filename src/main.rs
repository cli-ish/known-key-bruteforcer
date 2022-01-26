use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::env;
use std::thread;
use std::thread::JoinHandle;
use sha1::{Sha1};
use hmac::{Hmac, Mac};
use chrono;

type HmacSha1 = Hmac<Sha1>;

extern crate base64;
extern crate benchmarking;

fn read_hashes<P>(filename: P) -> (Vec<[u8; 20]>, Vec<[u8; 20]>) where P: AsRef<Path>, {
    let mut salt_list: Vec<[u8; 20]> = Vec::new();
    let mut base64_list: Vec<[u8; 20]> = Vec::new();
    let file = File::open(filename).unwrap();
    let reader = io::BufReader::new(file);
    for line in reader.lines() {
        let ele = line.unwrap();
        let elements: Vec<&str> = ele.split(" ").collect();
        if elements.len() > 0 {
            let parts: Vec<&str> = elements[0].split("|").collect();
            if parts.len() > 1 && parts[1].eq("1") {
                let mut base64_decode = base64::decode(parts[2].to_string()).unwrap();
                let mut x = vec_to_u8(base64_decode);
                salt_list.push(x);
                base64_decode = base64::decode(parts[3].to_string()).unwrap();
                x = vec_to_u8(base64_decode);
                base64_list.push(x);
            }
        }
    }
    return (salt_list, base64_list);
}

fn vec_to_u8(result: Vec<u8>) -> [u8; 20] {
    return [
        result[0],
        result[1],
        result[2],
        result[3],
        result[4],
        result[5],
        result[6],
        result[7],
        result[8],
        result[9],
        result[10],
        result[11],
        result[12],
        result[13],
        result[14],
        result[15],
        result[16],
        result[17],
        result[18],
        result[19]
    ];
}


fn hash_hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC size");
    mac.update(message);
    return vec_to_u8(mac.finalize().into_bytes().to_vec());
}

fn bruteforce_sha1_hash(ip: u64, salts: Vec<[u8; 20]>, base64: Vec<[u8; 20]>) -> bool {
    let ip_str: String = longip_to_string(ip);
    let ip: &[u8] = ip_str.as_bytes();
    let mut c: usize = 0;
    for i in salts {
        let code_bytes = hash_hmac_sha1(&i, ip);
        let cmp: [u8; 20] = base64[c];
        if code_bytes == cmp {
            println!("{}", ip_str)
        }
        c += 1;
    }
    return false;
}

fn bruteforce_ip_range(thread_count: u64, salt_list: Vec<[u8; 20]>, base64_list: Vec<[u8; 20]>, from: u64, to: u64, benchmark: bool) {
    let task_volume: u64 = to - from;
    let task_steps: u64 = task_volume / thread_count;
    let mut task_current: u64 = from;
    let mut threads: Vec<JoinHandle<_>> = Vec::new();
    for _t in 0..thread_count {
        let hc_base64s = base64_list.clone();
        let hc_salts = salt_list.clone();
        let task_from: u64 = task_current;
        let task_to: u64 = task_current + task_steps;
        task_current += task_steps;
        if !benchmark {
            println!("From {} -> {}", task_from, task_to);
        }
        let handle: thread::JoinHandle<_> = thread::spawn(move || {
            for longip in task_from..task_to {
                let base64s = hc_base64s.clone();
                let salts = hc_salts.clone();
                bruteforce_sha1_hash(longip, salts, base64s);
            }
        });
        threads.push(handle);
    }
    for _t in 0..thread_count {
        let thread = threads.pop().unwrap();
        thread.join().unwrap();
    }
}

fn longip_to_string(longip: u64) -> String {
    let pow1: u64 = 16777216;
    let pow2: u64 = 65536;
    let pow3: u64 = 256;
    let ip1: u64 = longip / pow1;
    let ip2: u64 = (longip % pow1) / pow2;
    let ip3: u64 = ((longip % pow1) % pow2) / pow3;
    let ip4: u64 = (((longip % pow1) % pow2) % pow3) / 1;
    return format!("{}.{}.{}.{}", ip1, ip2, ip3, ip4);
}

fn ip_to_longip(ip: String) -> u64 {
    let parts: Vec<&str> = ip.split(".").collect();
    if parts.len() == 4 {
        let ip1: u64 = parts[0].parse::<u64>().unwrap();
        let ip2: u64 = parts[1].parse::<u64>().unwrap();
        let ip3: u64 = parts[2].parse::<u64>().unwrap();
        let ip4: u64 = parts[3].parse::<u64>().unwrap();
        return ip1 * 16777216 + ip2 * 65536 + ip3 * 256 + ip4 * 1;
    }
    return 0;
}

fn benchmark_bruteforce(thread_count: u64, ip_count: u64, filename: String) -> u64 {
    let (salt_list, base64_list) = read_hashes(filename);
    let totallen: u64 = salt_list.len() as u64;
    let bench_result = benchmarking::measure_function(move |measurer| {
        let b = base64_list.clone();
        let s = salt_list.clone();
        measurer.measure(|| {
            bruteforce_ip_range(thread_count, s, b, 4294967297, 4294967297 + ip_count, true);
        });
    }).unwrap();
    let time = bench_result.elapsed().as_millis();
    let total = ip_count * totallen;
    let time_each_hash: u64 = total / (time as u64);
    println!("[*] Test: Cracking {} ips with each {} Entries equals to {} Hashes Took {:?} averaging with: {} per ms",
             ip_count * thread_count, totallen, total, bench_result.elapsed(), time_each_hash);
    return time_each_hash;
}

fn print_help() {
    println!("Usage example: ./known-key-bruteforcer -f /home/vince/.ssh/known_hosts -t 7 -s 65.0.0.0 -e 66.0.0.0");
    println!(" -f known_hosts file to bruteforce   (Default $Home/.ssh/known_hosts)");
    println!(" -t Thread count for the bruteforcer (Default 1)");
    println!(" -s Start of ip range                (Default 0.0.0.1)");
    println!(" -e End of ip range                  (Default 0.0.0.200)");
    println!(" -h Help");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut filename: String = String::from("");
    let mut thread_count: u64 = 1;
    let mut from_ip: u64 = 1; // 1000000000
    let mut to_ip: u64 = 200;
    let mut start_ip: String = String::from("");
    let mut end_ip: String = String::from("");
    if let Ok(user_home) = env::var("HOME") {
        filename = user_home.clone() + "/.ssh/known_hosts";
    }
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-h" || args[i] == "--help" {
            print_help();
            return;
        } else if (args[i] == "-f" || args[i] == "--file") && i < args.len() - 1 {
            filename = args[i + 1].clone();
            i += 1;
        } else if (args[i] == "-t" || args[i] == "--threads") && i < args.len() - 1 {
            thread_count = args[i + 1].clone().parse::<u64>().unwrap();
            i += 1;
        } else if (args[i] == "-s" || args[i] == "--start-ip") && i < args.len() - 1 {
            start_ip = args[i + 1].clone();
            let tmp_ip: u64 = ip_to_longip(start_ip.clone());
            if tmp_ip == 0 {
                print!("Error {} is not a valid ip!", args[i + 1].clone());
                print_help();
                return;
            }
            from_ip = tmp_ip;
            i += 1;
        } else if (args[i] == "-e" || args[i] == "--end-ip") && i < args.len() - 1 {
            end_ip = args[i + 1].clone();
            let tmp_ip: u64 = ip_to_longip(end_ip.clone());
            if tmp_ip == 0 {
                print!("Error {} is not a valid ip!", args[i + 1].clone());
                print_help();
                return;
            }
            to_ip = tmp_ip;
            i += 1;
        }
        i += 1;
    }
    if to_ip < from_ip {
        print!("start-ip is bigger than end-ip ???");
        print_help();
        return;
    }
    println!("Cracking: {} with {} Threads.", filename, thread_count);
    println!("Assumed ip range: {} - {}", start_ip, end_ip);
    println!("Start benchmark to calculate the time needed...");
    let (salt_list, base64_list) = read_hashes(filename.clone());
    let current_time = benchmark_bruteforce(thread_count, 1000 * thread_count, filename.clone()) * 1000;
    let workingtime_s: u64 = ((salt_list.len() as u64) * (to_ip - from_ip)) / current_time;
    let workingtime_m: u64 = workingtime_s / 60;
    let workingtime_h: u64 = workingtime_m / 60;
    let workingtime_d: u64 = workingtime_h / 24;
    println!("Calculated working time is {}s -> {}m -> {}h -> {}d", workingtime_s, workingtime_m, workingtime_h, workingtime_d);
    println!("Start time: {:?}", chrono::offset::Local::now());
    bruteforce_ip_range(thread_count, salt_list, base64_list, from_ip, to_ip, false);
    println!("End time: {:?}", chrono::offset::Local::now());
}