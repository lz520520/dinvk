use dinvk::hash::*;

fn main() {
    println!("{}", jenkins("dinvk"));
    println!("{}", jenkins3("dinvk"));
    println!("{}", ap("dinvk"));
    println!("{}", js("dinvk"));
    println!("{}", murmur3("dinvk"));
    println!("{}", fnv1a("dinvk"));
    println!("{}", djb2("dinvk"));
    println!("{}", crc32ba("dinvk"));
    println!("{}", loselose("dinvk"));
    println!("{}", pjw("dinvk"));
    println!("{}", sdbm("dinvk"));
}