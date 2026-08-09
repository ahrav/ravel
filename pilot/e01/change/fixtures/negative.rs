fn unwrap() -> u32 {
    1
}

fn main() {
    let v: Option<u32> = Some(1);
    let a = v.unwrap_or(0);
    let b = v.unwrap_or_default();
    let c = unwrap();
    let s = "unwrap";
    println!("{a} {b} {c} {s}");
}
