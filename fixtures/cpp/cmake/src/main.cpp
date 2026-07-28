#include <cstdio>

#include "geometry.hpp"

int main() {
  const std::vector<geometry::Point> square = {
      {0.0, 0.0}, {1.0, 0.0}, {1.0, 1.0}, {0.0, 1.0}};
  std::printf("perimeter %f\n", geometry::perimeter(square));
  std::printf("area %f\n", geometry::double_area(square) / 2.0);
  return 0;
}
