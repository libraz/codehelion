#pragma once

#include <vector>

namespace geometry {

/// A point on the plane.
struct Point {
  double x;
  double y;
};

/// The perimeter of the polygon through the given points.
double perimeter(const std::vector<Point>& points);

/// Twice the signed area of the polygon through the given points.
///
/// Near-identical to perimeter() in shape: same traversal, same wraparound,
/// different accumulation. What separates them is a compiler question rather
/// than a textual one.
double double_area(const std::vector<Point>& points);

}  // namespace geometry
