fn main() {
    let value: Option<u32> = Some(1);
    let n = value.unwrap();
    println!("{n}");
}
