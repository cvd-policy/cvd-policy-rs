//! Exact mathematical comparisons for arbitrary-precision JSON numbers.

use std::cmp::Ordering;

use num_bigint::BigInt;
use serde_json::Number;

/// Compares two JSON numbers by exact mathematical value.
///
/// Decimal coefficients are compared as digit strings, and arbitrary-size
/// exponents are handled with integer arithmetic. No power of ten is built.
pub(crate) fn compare(left: &Number, right: &Number) -> Ordering {
    match (decimal(left), decimal(right)) {
        (Some(left), Some(right)) => compare_decimals(&left, &right),
        // serde_json::Number normally guarantees valid JSON syntax. This fallback
        // keeps the function total if a caller uses its hidden unchecked constructor.
        _ => left.as_str().cmp(right.as_str()),
    }
}

/// Returns whether a JSON number has an integral mathematical value.
pub(crate) fn is_integer(number: &Number) -> bool {
    decimal(number)
        .is_some_and(|value| value.coefficient == "0" || value.scale >= BigInt::from(0_u8))
}

/// Returns whether a JSON number is mathematically greater than zero.
pub(crate) fn is_positive(number: &Number) -> bool {
    decimal(number).is_some_and(|value| value.coefficient != "0" && !value.negative)
}

struct Decimal {
    negative: bool,
    coefficient: String,
    scale: BigInt,
}

fn decimal(number: &Number) -> Option<Decimal> {
    let source = number.as_str();
    let bytes = source.as_bytes();
    let mut index = 0;
    let negative = if bytes.first() == Some(&b'-') {
        index += 1;
        true
    } else {
        false
    };

    let integer_start = index;
    match bytes.get(index).copied()? {
        b'0' => {
            index += 1;
            if bytes.get(index).is_some_and(|digit| digit.is_ascii_digit()) {
                return None;
            }
        }
        b'1'..=b'9' => {
            index += 1;
            while bytes.get(index).is_some_and(|digit| digit.is_ascii_digit()) {
                index += 1;
            }
        }
        _ => return None,
    }

    let integer_end = index;
    let mut coefficient = String::with_capacity(bytes.len());
    coefficient.push_str(&source[integer_start..integer_end]);

    let mut fraction_len = 0_usize;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let fraction_start = index;
        while bytes.get(index).is_some_and(|digit| digit.is_ascii_digit()) {
            index += 1;
        }
        fraction_len = index - fraction_start;
        if fraction_len == 0 {
            return None;
        }
        coefficient.push_str(&source[fraction_start..index]);
    }

    let mut exponent = BigInt::from(0_u8);
    if bytes
        .get(index)
        .is_some_and(|byte| matches!(*byte, b'e' | b'E'))
    {
        index += 1;
        let exponent_negative = match bytes.get(index) {
            Some(b'-') => {
                index += 1;
                true
            }
            Some(b'+') => {
                index += 1;
                false
            }
            _ => false,
        };
        let exponent_start = index;
        while bytes.get(index).is_some_and(|digit| digit.is_ascii_digit()) {
            index += 1;
        }
        if exponent_start == index {
            return None;
        }
        exponent = BigInt::parse_bytes(&bytes[exponent_start..index], 10)?;
        if exponent_negative {
            exponent = -exponent;
        }
    }

    if index != bytes.len() {
        return None;
    }

    let first_nonzero = coefficient.bytes().position(|digit| digit != b'0');
    let Some(first_nonzero) = first_nonzero else {
        return Some(Decimal {
            negative: false,
            coefficient: "0".to_owned(),
            scale: BigInt::from(0_u8),
        });
    };
    if first_nonzero > 0 {
        coefficient = coefficient.split_off(first_nonzero);
    }

    exponent -= BigInt::from(fraction_len);
    let last_nonzero = coefficient.bytes().rposition(|digit| digit != b'0')?;
    let trailing_zeros = coefficient.len() - last_nonzero - 1;
    coefficient.truncate(last_nonzero + 1);
    exponent += BigInt::from(trailing_zeros);

    Some(Decimal {
        negative,
        coefficient,
        scale: exponent,
    })
}

fn compare_decimals(left: &Decimal, right: &Decimal) -> Ordering {
    let left_zero = left.coefficient == "0";
    let right_zero = right.coefficient == "0";
    match (left_zero, right_zero) {
        (true, true) => return Ordering::Equal,
        (true, false) => {
            return if right.negative {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        }
        (false, true) => {
            return if left.negative {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
        (false, false) => {}
    }

    if left.negative != right.negative {
        return if left.negative {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }

    let left_magnitude = &left.scale + BigInt::from(left.coefficient.len());
    let right_magnitude = &right.scale + BigInt::from(right.coefficient.len());
    let magnitude_order = left_magnitude.cmp(&right_magnitude).then_with(|| {
        let length = left.coefficient.len().max(right.coefficient.len());
        for index in 0..length {
            let left_digit = left
                .coefficient
                .as_bytes()
                .get(index)
                .copied()
                .unwrap_or(b'0');
            let right_digit = right
                .coefficient
                .as_bytes()
                .get(index)
                .copied()
                .unwrap_or(b'0');
            match left_digit.cmp(&right_digit) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        Ordering::Equal
    });

    if left.negative {
        magnitude_order.reverse()
    } else {
        magnitude_order
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use serde_json::Number;

    use super::{compare, is_integer, is_positive};

    fn number(source: &str) -> Number {
        serde_json::from_str(source).unwrap()
    }

    #[test]
    fn compares_equivalent_decimal_spellings_as_equal() {
        let one = number("1");
        for equivalent in ["1.0", "1e0", "10e-1", "1000e-3"] {
            assert_eq!(compare(&one, &number(equivalent)), Ordering::Equal);
        }
        assert_eq!(
            compare(&number("-0"), &number("0.000e400")),
            Ordering::Equal
        );
    }

    #[test]
    fn compares_large_and_tiny_exponents_without_float_conversion() {
        assert_eq!(compare(&number("1e400"), &number("2e400")), Ordering::Less);
        assert_eq!(
            compare(&number("2e400"), &number("1e400")),
            Ordering::Greater
        );
        assert_eq!(
            compare(&number("1e-400"), &number("2e-400")),
            Ordering::Less
        );
        assert_eq!(
            compare(&number("9007199254740993"), &number("9007199254740992")),
            Ordering::Greater
        );
    }

    #[test]
    fn compares_signed_decimals_and_zero_correctly() {
        assert_eq!(compare(&number("-1.2"), &number("-1.19")), Ordering::Less);
        assert_eq!(compare(&number("-0.1"), &number("0")), Ordering::Less);
        assert_eq!(compare(&number("0"), &number("0.0001")), Ordering::Less);
    }

    #[test]
    fn detects_integer_and_positive_values_mathematically() {
        for value in ["1", "1.0", "10e-1", "1e400", "-0.0"] {
            assert!(is_integer(&number(value)), "{value}");
        }
        for value in ["1.1", "1e-400", "-1.1"] {
            assert!(!is_integer(&number(value)), "{value}");
        }
        assert!(is_positive(&number("1e-400")));
        assert!(is_positive(&number("1e400")));
        assert!(!is_positive(&number("0")));
        assert!(!is_positive(&number("-0.0")));
        assert!(!is_positive(&number("-1e400")));
    }
}
