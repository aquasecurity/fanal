package docker

import (
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/knqyf263/fanal/extractor"
)

func TestExtractFromFile(t *testing.T) {
	vectors := []struct {
		file      string            // Test input file
		filenames []string          // Target files
		FileMap   extractor.FileMap // Expected output
		err       error             // Expected error to occur
	}{
		{
			file:      "testdata/image1.tar",
			filenames: []string{"var/foo", "etc/test/bar"},
			FileMap: extractor.FileMap{
				"etc/test/bar": []byte("bar\n"),
				"/command":     []byte(`[{"Created":"2019-03-07T22:19:46.661698137Z","created_by":"/bin/sh -c #(nop) ADD file:38bc6b51693b13d84a63e281403e2f6d0218c44b1d7ff12157c4523f9f0ebb1e in / "},{"Created":"2019-03-07T22:19:46.815331171Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]"},{"Created":"2019-04-07T04:08:02.548475493Z","created_by":"/bin/sh -c mkdir /etc/test \u0026\u0026 touch /var/foo \u0026\u0026 touch /etc/test/test"},{"Created":"2019-04-07T04:27:16.291049098Z","created_by":"/bin/sh -c rm /var/foo \u0026\u0026 rm -rf /etc/test \u0026\u0026 mkdir /etc/test \u0026\u0026 echo bar \u003e /etc/test/bar"}]`),
			},
			err: nil,
		},
		{
			file:      "testdata/image2.tar",
			filenames: []string{"home/app/Gemfile", "home/app2/Gemfile"},
			FileMap: extractor.FileMap{
				"home/app2/Gemfile": []byte("gem"),
				"/command":          []byte(`[{"Created":"2019-03-07T22:19:46.661698137Z","created_by":"/bin/sh -c #(nop) ADD file:38bc6b51693b13d84a63e281403e2f6d0218c44b1d7ff12157c4523f9f0ebb1e in / "},{"Created":"2019-03-07T22:19:46.815331171Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]"},{"Created":"2019-04-07T05:32:58.27180871Z","created_by":"/bin/sh -c mkdir /home/app \u0026\u0026 echo -n gem \u003e /home/app/Gemfile"},{"Created":"2019-04-07T05:32:59.607884934Z","created_by":"/bin/sh -c mv /home/app /home/app2"}]`),
			},
			err: nil,
		},
		{
			file:      "testdata/image3.tar",
			filenames: []string{"home/app/Gemfile", "home/app2/Pipfile", "home/app/Pipfile"},
			FileMap: extractor.FileMap{
				"home/app/Pipfile": []byte("pip"),
				"/command":         []byte(`[{"Created":"2019-03-07T22:19:46.661698137Z","created_by":"/bin/sh -c #(nop) ADD file:38bc6b51693b13d84a63e281403e2f6d0218c44b1d7ff12157c4523f9f0ebb1e in / "},{"Created":"2019-03-07T22:19:46.815331171Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]"},{"Created":"2019-04-07T05:32:58.27180871Z","created_by":"/bin/sh -c mkdir /home/app \u0026\u0026 echo -n gem \u003e /home/app/Gemfile"},{"Created":"2019-04-07T05:36:07.629894435Z","created_by":"/bin/sh -c mkdir /home/app2 \u0026\u0026 echo -n pip \u003e /home/app2/Pipfile"},{"Created":"2019-04-07T05:36:08.899764053Z","created_by":"/bin/sh -c rm -rf /home/app \u0026\u0026 mv /home/app2 /home/app"}]`),
			},
			err: nil,
		},
		{
			file:      "testdata/image4.tar",
			filenames: []string{".abc", ".def", "foo/.abc", "foo/.def", ".foo/.abc"},
			FileMap: extractor.FileMap{
				".def":     []byte("def"),
				"foo/.abc": []byte("abc"),
				"/command": []byte(`[{"Created":"2019-03-07T22:19:46.661698137Z","created_by":"/bin/sh -c #(nop) ADD file:38bc6b51693b13d84a63e281403e2f6d0218c44b1d7ff12157c4523f9f0ebb1e in / "},{"Created":"2019-03-07T22:19:46.815331171Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]"},{"Created":"2019-04-07T05:48:10.560447082Z","created_by":"/bin/sh -c echo -n abc \u003e .abc \u0026\u0026 echo -n def \u003e .def"},{"Created":"2019-04-07T05:48:11.938256528Z","created_by":"/bin/sh -c mkdir foo \u0026\u0026 echo -n abc \u003e /foo/.abc \u0026\u0026 echo -n def \u003e /foo/.def"},{"Created":"2019-04-07T05:48:13.188275588Z","created_by":"/bin/sh -c rm .abc /foo/.def"},{"Created":"2019-04-07T05:48:14.569944213Z","created_by":"/bin/sh -c mkdir .foo \u0026\u0026 echo -n abc /.foo/.abc"},{"Created":"2019-04-07T05:48:16.088980845Z","created_by":"/bin/sh -c rm -rf /.foo"}]`),
			},
			err: nil,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			if err != nil {
				t.Fatalf("Open() error: %v", err)
			}
			defer f.Close()

			d := DockerExtractor{}
			fm, err := d.ExtractFromFile(nil, f, v.filenames)
			if v.err != err {
				t.Errorf("err: got %v, want %v", v.err, err)
			}
			if !reflect.DeepEqual(fm, v.FileMap) {
				t.Errorf("FilesMap: got %v, want %v", fm, v.FileMap)
			}
		})
	}
}

func TestExtractFiles(t *testing.T) {
	vectors := []struct {
		file      string            // Test input file
		filenames []string          // Target files
		FileMap   extractor.FileMap // Expected output
		opqDirs   opqDirs           // Expected output
		err       error             // Expected error to occur
	}{
		{
			file:      "testdata/normal.tar",
			filenames: []string{"var/foo"},
			FileMap:   extractor.FileMap{"var/foo": []byte{}},
			opqDirs:   []string{},
			err:       nil,
		},
		{
			file:      "testdata/opq.tar",
			filenames: []string{"var/foo"},
			FileMap: extractor.FileMap{
				"var/.wh.foo": []byte{},
			},
			opqDirs: []string{"etc/test"},
			err:     nil,
		},
		{
			file:      "testdata/opq2.tar",
			filenames: []string{"var/foo", "etc/test/bar"},
			FileMap: extractor.FileMap{
				"etc/test/bar": []byte("bar\n"),
				"var/.wh.foo":  []byte{},
			},
			opqDirs: []string{"etc/test"},
			err:     nil,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			if err != nil {
				t.Fatalf("Open() error: %v", err)
			}
			defer f.Close()

			d := DockerExtractor{}
			fm, opqDirs, err := d.ExtractFiles(f, v.filenames)
			if v.err != err {
				t.Errorf("err: got %v, want %v", v.err, err)
			}
			if !reflect.DeepEqual(opqDirs, v.opqDirs) {
				t.Errorf("opqDirs: got %v, want %v", opqDirs, v.opqDirs)
			}
			if !reflect.DeepEqual(fm, v.FileMap) {
				t.Errorf("FilesMap: got %v, want %v", fm, v.FileMap)
			}
		})
	}
}
