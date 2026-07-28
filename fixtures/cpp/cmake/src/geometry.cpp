#include "geometry.hpp"

#include <cmath>

namespace geometry {

double perimeter(const std::vector<Point>& points) {
  double total = 0.0;
  for (std::size_t i = 0; i < points.size(); ++i) {
    const Point& from = points[i];
    const Point& to = points[(i + 1) % points.size()];
    total += std::hypot(to.x - from.x, to.y - from.y);
  }
  return total;
}

double double_area(const std::vector<Point>& points) {
  double total = 0.0;
  for (std::size_t i = 0; i < points.size(); ++i) {
    const Point& from = points[i];
    const Point& to = points[(i + 1) % points.size()];
    total += (from.x * to.y) - (to.x * from.y);
  }
  return total;
}

}  // namespace geometry
