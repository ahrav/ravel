fn main() {
    let value: Option<u32> = Some(1);
    let n = value.expect("value is Some(1) by construction");
    println!("{n}");
}
