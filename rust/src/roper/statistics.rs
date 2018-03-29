

pub fn standard_deviation (v: &Vec<f32>) -> f32 {
        let m = mean(v);
        (v.iter()
            .map(|&x| (x - m).powi(2))
            .sum::<f32>() / v.len() as f32).sqrt()
}

pub fn mean (v: &Vec<f32>) -> f32 {
        v.iter()
          .sum::<f32>() / v.len() as f32
}
