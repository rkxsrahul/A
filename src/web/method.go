package web

import (
	"io/ioutil"
	"strings"
)

func findCategory(mapd map[string]string) string {
	for _, v := range mapd {
		return v
	}
	return ""
}

func headerFileSlug(header string) string {
	header = strings.ToLower(header)
	header = strings.Replace(header, " ", "-", -1)
	header = strings.Replace(header, "/", "-", -1)
	return header + ".sh"
}

func findLogoImagePath(resName string) string {
	logofiles, err := ioutil.ReadDir("./icons")
	if err != nil {
		return ""
	}
	var max float64
	var name string
	for _, f := range logofiles {
		if !(f.IsDir()) {
			sim := jaroSimilarity(strings.ToLower(resName), strings.ToLower(f.Name()))
			if sim == float64(1) {
				return f.Name()
			}
			if max < sim {
				max = sim
				name = f.Name()
			}
		}
	}

	if max == 0 {
		return ""
	}
	return name
}
