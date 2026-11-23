//go:build ignore

// Génère winres/icon.png et winres/icon16.png (éclair blanc sur fond dégradé).
// Usage : go run tools/genicon/main.go
package main

import (
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

// Polygone de l'éclair (coordonnées normalisées 0..1).
var bolt = [][2]float64{
	{0.58, 0.10}, {0.26, 0.56}, {0.47, 0.56}, {0.40, 0.90},
	{0.74, 0.42}, {0.53, 0.42}, {0.62, 0.10},
}

func inPoly(x, y float64) bool {
	in := false
	for i, j := 0, len(bolt)-1; i < len(bolt); j, i = i, i+1 {
		xi, yi := bolt[i][0], bolt[i][1]
		xj, yj := bolt[j][0], bolt[j][1]
		if (yi > y) != (yj > y) && x < (xj-xi)*(y-yi)/(yj-yi)+xi {
			in = !in
		}
	}
	return in
}

func render(size int) image.Image {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 4 // suréchantillonnage (anti-crénelage)
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/ss) / float64(size)
					y := (float64(py) + (float64(sy)+0.5)/ss) / float64(size)
					dx, dy := x-0.5, y-0.5
					if math.Hypot(dx, dy) > 0.48 {
						continue
					}
					if inPoly(x, y) {
						r, g, b = r+255, g+255, b+255
					} else {
						t := y
						r += 20 + 40*t
						g += 120 - 60*t
						b += 255 - 40*t
					}
					a += 255
				}
			}
			n := float64(ss * ss)
			if a > 0 {
				cov := a / 255
				img.SetNRGBA(px, py, color.NRGBA{uint8(r / cov), uint8(g / cov), uint8(b / cov), uint8(a / n)})
			}
		}
	}
	return img
}

func save(path string, size int) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := png.Encode(f, render(size)); err != nil {
		panic(err)
	}
}

func main() {
	save("winres/icon.png", 256)
	save("winres/icon16.png", 16)
}
