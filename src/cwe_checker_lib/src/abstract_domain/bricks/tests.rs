use std::collections::BTreeSet;

use crate::abstract_domain::bricks::widening::{
    INTERVAL_THRESHOLD, LENGTH_THRESHOLD, SEQUENCE_THRESHOLD,
};

use super::*;

impl Brick {
    fn mock_brick(sequence: Vec<String>, min: u32, max: u32) -> Brick {
        let mut mocked = Brick::new();
        mocked.set_sequence(sequence.into_iter().collect::<BTreeSet<String>>());
        mocked.set_min(min);
        mocked.set_max(max);

        mocked
    }
}

struct Setup {
    brick0: BrickDomain,
    brick1: BrickDomain,
    brick2: BrickDomain,
    brick3: BrickDomain,
    brick4: BrickDomain,
    brick5: BrickDomain,
}

impl Setup {
    fn new() -> Self {
        Setup {
            brick0: BrickDomain::Value(Brick::mock_brick(
                vec![String::from("a"), String::from("b")],
                2,
                2,
            )),
            brick1: BrickDomain::Value(Brick::mock_brick(
                vec![String::from("a"), String::from("cd")],
                1,
                1,
            )),
            brick2: BrickDomain::Value(Brick::mock_brick(
                vec![String::from("b"), String::from("ef")],
                1,
                1,
            )),
            brick3: BrickDomain::Value(Brick::mock_brick(
                vec![String::from("a"), String::from("b")],
                2,
                3,
            )),
            brick4: BrickDomain::Value(Brick::mock_brick(
                vec![String::from("a"), String::from("b")],
                0,
                1,
            )),
            brick5: BrickDomain::Value(Brick::mock_brick(vec![String::from("a")], 1, 1)),
        }
    }
}

#[test]
fn test_merge_brick_domain() {
    let setup = Setup::new();
    let merged_brick_domain = setup.brick0.merge(&setup.brick4);
    let expected = BrickDomain::Value(Brick::mock_brick(
        vec![String::from("a"), String::from("b")],
        0,
        2,
    ));

    assert_eq!(merged_brick_domain, expected);
}

#[test]
fn test_brick_is_less_or_equal() {
    let setup = Setup::new();
    // Test Case 1: brick0 = {a,b}^[2,2] is less than brick3 = {a,b}^[2,3]
    assert!(setup.brick0.is_less_or_equal(&setup.brick3));
    // Test Case 2: brick0 = {a,b}^[2,2] is less than Top
    assert!(setup.brick0.is_less_or_equal(&BrickDomain::Top));
    // Test Case 3: Top is not less than brick0 = {a,b}^[2,2]
    assert!(!BrickDomain::Top.is_less_or_equal(&setup.brick0));
    // Test Case 4: Top is less than Top
    assert!(BrickDomain::Top.is_less_or_equal(&BrickDomain::Top));
    // Test Case 5: self represents an empty string and the other is a 'normal' brick.
    assert!(BrickDomain::get_empty_brick_domain().is_less_or_equal(&setup.brick0));
    // Test Case 6: other represents an empty string and self is a 'normal' brick.
    assert!(setup
        .brick0
        .is_less_or_equal(&BrickDomain::get_empty_brick_domain()));
}

#[test]
fn test_brick_widen() {
    let setup = Setup::new();

    // Test Case 1: No widening is applied since no thresholds are exceeded.
    let widened_brick_domain = setup.brick0.widen(&setup.brick4);
    let expected = BrickDomain::Value(Brick::mock_brick(
        vec![String::from("a"), String::from("b")],
        0,
        2,
    ));

    assert_eq!(widened_brick_domain, expected);

    // Test Case 2: Widening is applied since the sequence threshold is exceeded.
    let large_sequence = (0..SEQUENCE_THRESHOLD)
        .collect::<Vec<usize>>()
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<String>>();
    let widened_brick_domain =
        setup
            .brick0
            .widen(&BrickDomain::Value(Brick::mock_brick(large_sequence, 0, 1)));

    assert_eq!(widened_brick_domain, BrickDomain::Top);

    // Test Case 3: Widening is applied since the interval threshold is exceeded.
    let high_bounded_brick = BrickDomain::Value(Brick::mock_brick(
        vec![String::from("a"), String::from("b")],
        0,
        (INTERVAL_THRESHOLD + 1) as u32,
    ));
    let widened_brick_domain = setup.brick0.widen(&high_bounded_brick);
    let expected = BrickDomain::Value(Brick::mock_brick(
        vec![String::from("a"), String::from("b")],
        0,
        u32::MAX,
    ));

    assert_eq!(widened_brick_domain, expected);
}

#[test]
fn test_merge_bricks_domain() {
    let setup = Setup::new();
    let first_bricks = BricksDomain::Value(vec![setup.brick0.clone()]);
    let second_bricks = BricksDomain::Value(vec![setup.brick0.clone(), setup.brick1.clone()]);

    let merged_bricks = first_bricks.merge(&second_bricks);

    let merged_with_empty = BrickDomain::Value(Brick::mock_brick(
        vec![String::from("a"), String::from("cd")],
        0,
        1,
    ));
    let normalized_brick = BrickDomain::Value(Brick::mock_brick(
        vec![
            "aa".to_string(),
            "ab".to_string(),
            "ba".to_string(),
            "bb".to_string(),
        ],
        1,
        1,
    ));
    let expected = BricksDomain::Value(vec![normalized_brick, merged_with_empty]);

    assert_eq!(merged_bricks, expected);
}

#[test]
fn test_bricks_is_less_or_equal() {
    let setup = Setup::new();
    let mut bricks1 = vec![
        setup.brick3,
        BrickDomain::Value(Brick::mock_brick(
            vec!["c".to_string(), "d".to_string()],
            4,
            5,
        )),
    ];
    let mut bricks2 = vec![
        BrickDomain::Value(Brick::mock_brick(
            vec!["a".to_string(), "b".to_string()],
            1,
            4,
        )),
        BrickDomain::Value(Brick::mock_brick(
            vec!["c".to_string(), "d".to_string(), "e".to_string()],
            4,
            5,
        )),
    ];

    // Test Case 1: bricks1 is less or equal to bricks2
    assert!(BricksDomain::Value(bricks1.clone())
        .is_less_or_equal(&BricksDomain::Value(bricks2.clone())));

    // Test Case 2: bricks1 is shorter than bricks2 and is extended with an empty string brick.
    // This does not change the outcome.
    bricks1.push(BrickDomain::get_empty_brick_domain());
    bricks2.push(setup.brick5);
    assert!(BricksDomain::Value(bricks1.clone())
        .is_less_or_equal(&BricksDomain::Value(bricks2.clone())));

    // Test Case 3: Top value in bricks1 and Top value in bricks2
    bricks1.push(BrickDomain::Top);
    bricks2.push(BrickDomain::Top);
    assert!(BricksDomain::Value(bricks1.clone())
        .is_less_or_equal(&BricksDomain::Value(bricks2.clone())));

    // Test Case 4: some value in bricks1 and Top value in bricks2
    bricks1.push(setup.brick4);
    bricks2.push(BrickDomain::Top);
    assert!(BricksDomain::Value(bricks1.clone())
        .is_less_or_equal(&BricksDomain::Value(bricks2.clone())));

    // Test Case 5: Top value in bricks1 and some value in bricks2
    bricks1.push(BrickDomain::Top);
    bricks2.push(setup.brick2);
    assert!(!BricksDomain::Value(bricks1.clone())
        .is_less_or_equal(&BricksDomain::Value(bricks2.clone())));
}

#[test]
fn test_bricks_widen() {
    let setup = Setup::new();
    let mut bricks1 = vec![
        setup.brick3,
        BrickDomain::Value(Brick::mock_brick(
            vec!["c".to_string(), "d".to_string()],
            4,
            5,
        )),
    ];
    let mut bricks2 = vec![
        BrickDomain::Value(Brick::mock_brick(
            vec!["a".to_string(), "b".to_string()],
            1,
            4,
        )),
        BrickDomain::Value(Brick::mock_brick(
            vec!["c".to_string(), "d".to_string(), "e".to_string()],
            4,
            5,
        )),
    ];

    // Test Case 1: The less or equal relation holds and no threshold is exceeded.
    // Equivalent to normal merge.
    assert_eq!(
        BricksDomain::Value(bricks1.clone()).widen(&BricksDomain::Value(bricks2.clone())),
        BricksDomain::Value(bricks2.clone())
    );

    // Test Case 2: The first BricksDomain exceeds the length threshold.
    let mut extended_bricks = bricks1.clone();
    for _ in 0..LENGTH_THRESHOLD {
        extended_bricks.push(BrickDomain::get_empty_brick_domain());
    }

    assert_eq!(
        BricksDomain::Value(extended_bricks.clone()).widen(&BricksDomain::Value(bricks2.clone())),
        BricksDomain::Top
    );

    // Test Case 3: The less or equal relation does not hold.
    bricks1.push(BrickDomain::Top);
    bricks2.push(setup.brick2);
    assert_eq!(
        BricksDomain::Value(bricks1.clone()).widen(&BricksDomain::Value(bricks2.clone())),
        BricksDomain::Top
    );
}

#[test]
fn test_brick_list_is_less_or_equal() {
    let setup = Setup::new();

    let first_bricks = BricksDomain::Value(vec![
        setup.brick0.clone(),
        BrickDomain::get_empty_brick_domain(),
    ]);
    let second_bricks = BricksDomain::Value(vec![setup.brick0.clone(), setup.brick1.clone()]);

    assert!(first_bricks.is_less_or_equal(&second_bricks));
}

#[test]
fn test_normalize() {
    let setup = Setup::new();
    let to_normalize: BricksDomain =
        BricksDomain::Value(vec![setup.brick5, setup.brick3, setup.brick4]); // ["a"]^{1,1}["a", "b"]^{2,3}["a", "b"]^{0,1}
    let normalized = to_normalize.normalize();

    let expected_brick1 = BrickDomain::Value(Brick::mock_brick(
        vec!["aaa", "aab", "aba", "abb"]
            .iter()
            .map(|&s| String::from(s))
            .collect(),
        1,
        1,
    ));

    let expected_brick2 = BrickDomain::Value(Brick::mock_brick(
        vec!["a", "b"].iter().map(|&s| String::from(s)).collect(),
        0,
        2,
    ));

    let expected = BricksDomain::Value(vec![expected_brick1, expected_brick2]);

    assert_eq!(normalized, expected);
}

#[test]
fn test_generate_permutations_of_fixed_length() {
    let length: usize = 2;
    let sequence: BTreeSet<String> = vec!["a", "b", "c"]
        .into_iter()
        .map(|s| String::from(s))
        .collect();
    let result = Brick::generate_permutations_of_fixed_length(length, &sequence, Vec::new());
    let expected: Vec<String> = vec!["aa", "ba", "ca", "ab", "bb", "cb", "ac", "bc", "cc"]
        .into_iter()
        .map(|s| String::from(s))
        .collect();

    assert_eq!(result, expected);
}

#[test]
fn test_break_single_brick_into_simpler_bricks() {
    let setup = Setup::new();
    let complex_brick = setup.brick3.unwrap_value(); // ["a", "b"]^{2,3}
    let (result1, result2) = complex_brick.break_single_brick_into_simpler_bricks();
    let expected_brick1 = Brick::mock_brick(
        vec!["aa", "ba", "ab", "bb"]
            .iter()
            .map(|&s| String::from(s))
            .collect(),
        1,
        1,
    );

    let expected_brick2 = Brick::mock_brick(
        vec!["a", "b"].iter().map(|&s| String::from(s)).collect(),
        0,
        1,
    );

    assert_eq!(result1, expected_brick1);
    assert_eq!(result2, expected_brick2);
}

#[test]
fn test_merge_bricks_with_equal_content() {
    let setup = Setup::new();
    let merge1 = setup.brick0.unwrap_value();
    let merge2 = setup.brick4.unwrap_value();

    let result = merge1.merge_bricks_with_equal_content(merge2);
    let expected = setup.brick3.unwrap_value();

    assert_eq!(result, expected);
}

#[test]
fn test_transform_brick_with_min_max_equal() {
    let setup = Setup::new();
    let not_normalized = setup.brick0.unwrap_value();
    let result =
        not_normalized.transform_brick_with_min_max_equal(not_normalized.get_min() as usize);
    let expected_brick = Brick::mock_brick(
        vec!["aa", "ba", "ab", "bb"]
            .iter()
            .map(|&s| String::from(s))
            .collect(),
        1,
        1,
    );

    assert_eq!(result, expected_brick);
}

#[test]
fn test_merge_bricks_with_bound_one() {
    let setup = Setup::new();
    let merge1 = setup.brick1.unwrap_value();
    let merge2 = setup.brick2.unwrap_value();

    let result = merge1.merge_bricks_with_bound_one(merge2);
    let expected_brick = Brick::mock_brick(
        vec!["ab", "aef", "cdb", "cdef"]
            .iter()
            .map(|&s| String::from(s))
            .collect(),
        1,
        1,
    );

    assert_eq!(result, expected_brick);
}

#[test]
fn test_empty_string() {
    let setup = Setup::new();
    let brick = setup.brick5.unwrap_value();
    let empty_brick = BrickDomain::get_empty_brick_domain().unwrap_value();

    assert!(!brick.is_empty_string());
    assert!(empty_brick.is_empty_string());
}

#[test]
fn test_pad_list() {
    let setup = Setup::new();
    let empty_brick = BrickDomain::get_empty_brick_domain();
    let short_list = vec![
        setup.brick0.clone(),
        setup.brick1.clone(),
        setup.brick2.clone(),
    ];
    let long_list = vec![
        setup.brick3,
        setup.brick0.clone(),
        setup.brick1.clone(),
        setup.brick4,
        setup.brick5,
    ];

    let new_list = BricksDomain::Value(short_list).pad_list(&BricksDomain::Value(long_list));
    let expected_list = BricksDomain::Value(vec![
        empty_brick.clone(),
        setup.brick0,
        setup.brick1,
        empty_brick.clone(),
        setup.brick2,
    ]);

    assert_eq!(new_list, expected_list);
}

#[test]
fn test_append_string_domain() {
    let bricks_one = BricksDomain::Value(vec![BrickDomain::Value(Brick::mock_brick(
        vec!["cat ".to_string()],
        1,
        1,
    ))]);
    let bricks_two = BricksDomain::Value(vec![BrickDomain::Value(Brick::mock_brick(
        vec!["bash.sh".to_string()],
        1,
        1,
    ))]);
    let top_bricks = BricksDomain::Top;

    assert_eq!(
        BricksDomain::Top,
        top_bricks.append_string_domain(&top_bricks)
    );

    let expected_bricks = BricksDomain::Value(vec![
        BrickDomain::Value(Brick::mock_brick(vec!["cat ".to_string()], 1, 1)),
        BrickDomain::Top,
    ]);
    assert_eq!(
        expected_bricks,
        bricks_one.append_string_domain(&top_bricks)
    );

    let expected_bricks = BricksDomain::Value(vec![
        BrickDomain::Top,
        BrickDomain::Value(Brick::mock_brick(vec!["bash.sh".to_string()], 1, 1)),
    ]);
    assert_eq!(
        expected_bricks,
        top_bricks.append_string_domain(&bricks_two)
    );

    let expected_bricks = BricksDomain::Value(vec![
        BrickDomain::Value(Brick::mock_brick(vec!["cat ".to_string()], 1, 1)),
        BrickDomain::Value(Brick::mock_brick(vec!["bash.sh".to_string()], 1, 1)),
    ]);
    assert_eq!(
        expected_bricks,
        bricks_one.append_string_domain(&bricks_two)
    );
}
