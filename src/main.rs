use std::thread::sleep;
use std::time::Duration;

use dllinject::{find_process_by_name, get_current_process, inject_local, inject_v2, load_library};

fn main() {
    // println!("Hello, world!");
    // println!("Hello, world! {:?}", std::iter::repeat(1).take(10).collect::<Box<[u32]>>().iter().size_hint());
    // println!("Process IDs: {:?}", get_process_ids());
    // println!("Chrome process name [ID {:?}] {:?}", 6648, get_process_name(&simple_open_process(6648)));
    // let ress = find_process_by_name("chrom");
    // ress.for_each(|proc| {
    //     println!("Process name: {}", get_process_name(&proc).unwrap());
    // });

    let target = find_process_by_name("testc").next().expect("target process not found");
    // let target = get_current_process();

    let path = "C:\\Users\\jitrs\\CLionProjects\\cpp20lib\\cmake-build-release\\libcpp20lib.dll";
    // let path = "C:\\Users\\jitrs\\CLionProjects\\dllinject\\popup\\target\\debug\\doge.dll";

    inject_v2(&target, path).unwrap();

    // inject(&target, path).unwrap();

    // inject_local("popup\\target\\debug\\doge.dll");

    // let dll = load_library(path);
    // assert!(!dll.is_null());

    sleep(Duration::from_secs(1));
}
