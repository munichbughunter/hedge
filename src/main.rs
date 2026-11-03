fn main() {
    println!("Hello, world!");
    println!("{}", greeting("Patrick"));
}

fn greeting(name: &str) -> String {
    format!("Hallo, {}!", name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_contains_name() {
        assert_eq!(greeting("Patrick"), "Hallo, Patrick!")
    }
}
