package helm

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_helmConfigAnalyzer_Analyze(t *testing.T) {
	type args struct {
		namespaces  []string
		policyPaths []string
	}
	tests := []struct {
		name      string
		args      args
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name: "Chart.yaml",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/Chart.yaml",
			want: &analyzer.AnalysisResult{
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type: "helm",
							Path: "testdata/Chart.yaml",
							Content: []byte(`apiVersion: v2
name: testchart
description: A Helm chart for Kubernetes

# A chart can be either an 'application' or a 'library' chart.
#
# Application charts are a collection of templates that can be packaged into versioned archives
# to be deployed.
#
# Library charts provide useful utilities or functions for the chart developer. They're included as
# a dependency of application charts to inject those utilities and functions into the rendering
# pipeline. Library charts do not define any templates and therefore cannot be deployed.
type: application

# This is the chart version. This version number should be incremented each time you make changes
# to the chart and its templates, including the app version.
# Versions are expected to follow Semantic Versioning (https://semver.org/)
version: 0.1.0

# This is the version number of the application being deployed. This version number should be
# incremented each time you make changes to the application. Versions are not expected to
# follow Semantic Versioning. They should reflect the version the application is using.
# It is recommended to use it with quotes.
appVersion: "1.16.0"
`),
						},
					},
				},
			},
		},
		{
			name: "values.yaml",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/values.yaml",
			want: &analyzer.AnalysisResult{
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type: "helm",
							Path: "testdata/values.yaml",
							Content: []byte(`# Default values for testchart.
# This is a YAML-formatted file.
# Declare variables to be passed into your templates.

replicaCount: 1

image:
  repository: nginx
  pullPolicy: IfNotPresent
  # Overrides the image tag whose default is the chart appVersion.
  tag: ""

imagePullSecrets: []
nameOverride: ""
fullnameOverride: ""

serviceAccount:
  # Specifies whether a service account should be created
  create: true
  # Annotations to add to the service account
  annotations: {}
  # The name of the service account to use.
  # If not set and create is true, a name is generated using the fullname template
  name: ""

podAnnotations: {}

podSecurityContext:
  {}
# fsGroup: 2000

securityContext:
  {}
  # capabilities:
  #   drop:
  #   - ALL
  # readOnlyRootFilesystem: true
  # runAsNonRoot: true
# runAsUser: 1000

service:
  type: ClusterIP
  port: 80

ingress:
  enabled: false
  className: ""
  annotations:
    {}
    # kubernetes.io/ingress.class: nginx
  # kubernetes.io/tls-acme: "true"
  hosts:
    - host: chart-example.local
      paths:
        - path: /
          pathType: ImplementationSpecific
  tls: []
  #  - secretName: chart-example-tls
  #    hosts:
  #      - chart-example.local

resources:
  {}
  # We usually recommend not to specify default resources and to leave this as a conscious
  # choice for the user. This also increases chances charts run on environments with little
  # resources, such as Minikube. If you do want to specify resources, uncomment the following
  # lines, adjust them as necessary, and remove the curly braces after 'resources:'.
  # limits:
  #   cpu: 100m
  #   memory: 128Mi
  # requests:
  #   cpu: 100m
#   memory: 128Mi

autoscaling:
  enabled: false
  minReplicas: 1
  maxReplicas: 100
  targetCPUUtilizationPercentage: 80
  # targetMemoryUtilizationPercentage: 80

nodeSelector: {}

tolerations: []

affinity: {}
`),
						},
					},
				},
			},
		},
		{
			name: "testchart.tgz",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/testchart.tgz",
			want: &analyzer.AnalysisResult{
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type: "helm",
							Path: "testdata/testchart.tgz",
							Content: []uint8{
								0x1f, 0x8b, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0xed, 0x58, 0x5b,
								0x6f, 0xdb, 0x36, 0x14, 0xce, 0xb3, 0x7e, 0x5, 0xd7, 0x3c, 0xa4, 0x2d, 0x1a, 0xd9,
								0x4a, 0xec, 0xa4, 0xf0, 0x5b, 0x90, 0xec, 0x12, 0x2c, 0x69, 0x83, 0xa6, 0xed, 0x30,
								0xc, 0xc3, 0x40, 0x4b, 0xb4, 0xcd, 0x85, 0x22, 0x55, 0x92, 0x72, 0xe2, 0xe, 0xdb,
								0x6f, 0xdf, 0x77, 0x48, 0xc9, 0x76, 0x9c, 0xa6, 0xed, 0x43, 0x9b, 0x62, 0x98, 0xce,
								0x83, 0x6d, 0x51, 0x87, 0xe7, 0x7e, 0xb5, 0x17, 0xce, 0xe7, 0x33, 0x6e, 0x7d, 0x6f,
								0xeb, 0xab, 0x41, 0x1f, 0x70, 0x38, 0x1c, 0xd2, 0x77, 0x76, 0x38, 0xec, 0xc7, 0xef,
								0xfd, 0xf0, 0xdd, 0xc2, 0x56, 0x36, 0xd8, 0x1b, 0x64, 0x7b, 0xd9, 0x60, 0x98, 0x1,
								0x2f, 0xcb, 0xe, 0x7, 0x87, 0x5b, 0x6c, 0xf8, 0xf5, 0x44, 0x5a, 0x41, 0xed, 0x3c, 0xb7,
								0x8c, 0x6d, 0x99, 0x6b, 0xa1, 0x3f, 0x8e, 0x27, 0xac, 0x7b, 0x8, 0x81, 0x1e, 0x16,
								0xfc, 0xd2, 0xff, 0xc7, 0xf4, 0x99, 0x2e, 0x78, 0xa9, 0xbe, 0x34, 0xf, 0x72, 0xf0,
								0xc1, 0x60, 0x70, 0x9f, 0xff, 0xf7, 0xb2, 0xc3, 0x2c, 0xf8, 0xbf, 0x3f, 0x18, 0xec,
								0xed, 0xf, 0xf6, 0xe0, 0xff, 0xfd, 0x83, 0xc3, 0xe1, 0x16, 0xeb, 0x7f, 0x69, 0x41,
								0x3e, 0x4, 0xff, 0x73, 0xff, 0xf3, 0x4a, 0xbe, 0x85, 0x62, 0xd2, 0xe8, 0x11, 0x9b,
								0xef, 0x25, 0x9a, 0x97, 0x62, 0xc4, 0x96, 0x41, 0x91, 0x14, 0xc2, 0xe5, 0x56,
								0x56, 0x3e, 0xbc, 0x3f, 0x62, 0x3f, 0x9, 0x55, 0xb2, 0xf0, 0x86, 0x4d, 0x8c, 0x65,
								0x3f, 0xd7, 0x63, 0x61, 0xb5, 0x0, 0x7a, 0x92, 0x6c, 0xe3, 0x75, 0x7c, 0x93, 0x73,
								0xcd, 0xc6, 0x82, 0x9, 0xe9, 0x67, 0xc2, 0x32, 0x3c, 0xec, 0xf0, 0xaa, 0x52, 0x32,
								0xe7, 0x44, 0x65, 0x87, 0xe1, 0x1e, 0x67, 0x3b, 0x4a, 0x8e, 0x2d, 0xb7, 0x8b, 0x9d,
								0x78, 0x27, 0x4d, 0xb6, 0x89, 0xc0, 0xa, 0x2d, 0x1e, 0x3b, 0xc6, 0xad, 0x0, 0x76, 0x6e,
								0x94, 0x12, 0x79, 0x38, 0x37, 0x13, 0x48, 0x57, 0x56, 0x8a, 0x83, 0x29, 0xf3, 0x33,
								0xbe, 0x64, 0x57, 0xf1, 0xfc, 0x8a, 0x4f, 0x45, 0xc1, 0xa4, 0xf6, 0x86, 0xcd, 0xa3,
								0x4e, 0x78, 0xe4, 0x36, 0x9f, 0xc9, 0x39, 0x24, 0xdc, 0x66, 0x38, 0x7, 0x62, 0x21,
								0x2a, 0x65, 0x16, 0xa2, 0x88, 0x3c, 0xcf, 0xa2, 0x1c, 0x2d, 0xbf, 0xca, 0x9a, 0xb9,
								0x2c, 0x4, 0x83, 0xb7, 0x27, 0xb5, 0x62, 0xb5, 0x97, 0x4a, 0x7a, 0x9, 0x56, 0x90,
								0x7a, 0x52, 0xeb, 0x20, 0x83, 0xb, 0xba, 0x43, 0xb9, 0x46, 0xdf, 0x42, 0xcc, 0x85,
								0x32, 0x95, 0xb0, 0x29, 0x7b, 0x3d, 0x13, 0x8b, 0x1d, 0x88, 0x2c, 0x75, 0xae, 0xea,
								0x82, 0xb8, 0x13, 0x5f, 0x4e, 0x3c, 0x85, 0x2e, 0x84, 0xce, 0x17, 0xa4, 0x0, 0xbf,
								0xab, 0x27, 0x44, 0x93, 0xfa, 0x4f, 0xe8, 0x8, 0xba, 0xc6, 0x89, 0x35, 0xc6, 0x5c,
								0x17, 0x6b, 0x9c, 0x83, 0x72, 0xc4, 0xda, 0x12, 0x3d, 0x2b, 0xf5, 0x14, 0xf4, 0x2b,
								0x59, 0x9, 0x25, 0xb5, 0x48, 0x37, 0xb5, 0x29, 0xc, 0xd3, 0x86, 0x4, 0x9c, 0xe0,
								0x2d, 0x28, 0x2d, 0xd6, 0x6c, 0x47, 0x74, 0xc9, 0x41, 0x2, 0xca, 0x8, 0x32, 0x22,
								0x61, 0xde, 0x32, 0x8f, 0x5f, 0x54, 0x88, 0x85, 0x35, 0x61, 0xc9, 0xc9, 0xaf, 0x67,
								0x12, 0x52, 0xb8, 0x35, 0xf5, 0x1b, 0x53, 0xa7, 0xf1, 0x55, 0xf3, 0xc4, 0x74, 0x5d,
								0x22, 0x36, 0x98, 0x9b, 0x99, 0x5a, 0x15, 0x44, 0x17, 0x26, 0xb1, 0xa2, 0x14, 0xda,
								0xc3, 0x2a, 0x82, 0xe7, 0x33, 0xe6, 0x65, 0x29, 0xd8, 0xc2, 0xd4, 0xac, 0xe4, 0x57,
								0x81, 0x96, 0x9e, 0xb6, 0x5e, 0x5a, 0x11, 0x27, 0x29, 0x25, 0xd9, 0xa7, 0x95, 0xfb,
								0x59, 0x63, 0x5b, 0x68, 0x1e, 0xd0, 0x20, 0xde, 0x52, 0x2, 0x5c, 0x6e, 0x62, 0x39,
								0x6, 0x8e, 0xb8, 0xa9, 0x60, 0x51, 0xf0, 0x3, 0xc9, 0x9, 0x42, 0xc8, 0x5c, 0xb3, 0x4b,
								0x51, 0x72, 0xed, 0x65, 0xde, 0x22, 0x12, 0x99, 0xc7, 0x33, 0xef, 0x2b, 0x37, 0xea,
								0xf5, 0x9c, 0x28, 0x41, 0x2a, 0x35, 0x76, 0xda, 0x7b, 0x92, 0xcc, 0xdb, 0xac, 0xe8,
								0xa7, 0x59, 0xda, 0xdf, 0x54, 0x7d, 0x43, 0x4d, 0x8a, 0xca, 0x28, 0xcc, 0xd2, 0xb1,
								0x63, 0x41, 0xb4, 0x97, 0xd6, 0xfc, 0xb8, 0x75, 0x40, 0xfd, 0xf3, 0xec, 0xd3, 0x5a,
								0x67, 0x8d, 0x53, 0x7a, 0x5b, 0x69, 0x72, 0xe3, 0x9a, 0xe2, 0xa0, 0x7c, 0xbf, 0xea,
								0x31, 0x60, 0x5b, 0x31, 0x10, 0xa, 0x2a, 0x46, 0xe0, 0x4a, 0xbf, 0x4d, 0xad, 0xa0,
								0x43, 0xed, 0xe8, 0x26, 0xe8, 0x9e, 0x7a, 0x7a, 0xb4, 0x22, 0x37, 0x65, 0x49, 0xd1,
								0x18, 0xec, 0x8c, 0xc4, 0x81, 0xc3, 0xd8, 0x35, 0x92, 0x9f, 0xbd, 0xab, 0xd, 0x3c,
								0x96, 0x26, 0x20, 0xb0, 0xac, 0x31, 0x8f, 0xb2, 0x34, 0x3b, 0x48, 0xfb, 0x8f, 0x92,
								0x6f, 0x5d, 0xf8, 0x3a, 0x8, 0xb0, 0xea, 0xff, 0xe9, 0xc, 0xc5, 0x5d, 0x4e, 0x35,
								0xca, 0xc1, 0x17, 0xe6, 0xf1, 0x89, 0xfe, 0xdf, 0x1f, 0xee, 0xf, 0x37, 0xfa, 0xff,
								0x20, 0xeb, 0xf, 0xba, 0xfe, 0xff, 0x10, 0xb0, 0xcd, 0x2e, 0xb8, 0xf7, 0xe8, 0xe2,
								0xb1, 0x7, 0x5, 0xf7, 0xb3, 0xeb, 0x99, 0x40, 0x1, 0xab, 0xa5, 0xa, 0x65, 0xb6, 0xe9,
								0xac, 0x2e, 0x6d, 0x6b, 0xa0, 0xab, 0xab, 0xca, 0x50, 0x7f, 0x71, 0x8, 0x19, 0xc5, 0xa6,
								0xca, 0x8c, 0x51, 0xa4, 0x10, 0x46, 0xc0, 0x7e, 0x86, 0x82, 0x80, 0x42, 0x8d, 0x8e,
								0x8b, 0x7b, 0xa8, 0x1, 0xab, 0x73, 0x94, 0x72, 0x10, 0xd0, 0x62, 0x1a, 0x2b, 0xc9,
								0xe3, 0xa, 0xf5, 0x46, 0xde, 0xa0, 0x6a, 0x84, 0x5a, 0xf1, 0xdd, 0x93, 0x94, 0xbd,
								0xd4, 0xa, 0xfd, 0x51, 0x87, 0x9b, 0x24, 0x12, 0x43, 0x4f, 0x65, 0xa1, 0xb1, 0x25,
								0xe9, 0xc9, 0xe5, 0x1f, 0x97, 0x1e, 0xb2, 0x81, 0xc4, 0x31, 0xea, 0xd, 0x8, 0xbc,
								0x3d, 0xbe, 0x64, 0x85, 0xb4, 0x2e, 0x49, 0xa7, 0xd2, 0xf7, 0xc2, 0x67, 0x14, 0x3f,
								0x49, 0xc7, 0xef, 0x6d, 0x2f, 0x7c, 0xb6, 0x7, 0xb3, 0x69, 0x8f, 0x3e, 0xda, 0x47,
								0x37, 0xd7, 0xbd, 0x15, 0xa1, 0x31, 0xf4, 0xab, 0x2b, 0x36, 0x91, 0xa, 0xfd, 0xe7,
								0x69, 0xea, 0xae, 0x2b, 0x7c, 0x8e, 0xf9, 0x15, 0x3e, 0x7d, 0x49, 0xbf, 0xd, 0xe8,
								0x24, 0x4f, 0xff, 0xa1, 0xf6, 0xc2, 0xad, 0x34, 0xb5, 0x63, 0xa7, 0x27, 0xdf, 0x83,
								0x2f, 0x86, 0x5, 0x6a, 0xd9, 0x49, 0x8a, 0x89, 0x81, 0xf7, 0x22, 0x3a, 0x8e, 0x92,
								0x74, 0xee, 0x72, 0x53, 0x88, 0xde, 0x7f, 0xa1, 0xc6, 0xad, 0xf2, 0x7f, 0xce, 0x55,
								0xd, 0x27, 0x7f, 0x85, 0x5, 0xe0, 0x13, 0xf9, 0xbf, 0x3f, 0xdc, 0x3f, 0xb8, 0x93,
								0xff, 0x83, 0xac, 0xcb, 0xff, 0x87, 0x80, 0x6d, 0x76, 0x22, 0x26, 0xbc, 0x56, 0x98,
								0xe3, 0x82, 0xff, 0xe3, 0x6c, 0xdb, 0x6, 0x45, 0xba, 0x36, 0xf6, 0x70, 0xf6, 0xeb,
								0xd1, 0xf9, 0xd9, 0x2e, 0xde, 0x97, 0x94, 0x9e, 0x45, 0x48, 0x18, 0x42, 0x38, 0x11,
								0xb9, 0xa2, 0xc9, 0x63, 0x8e, 0xe4, 0xe0, 0x63, 0x15, 0x87, 0x94, 0x30, 0x91, 0x3b,
								0xd7, 0xce, 0xe3, 0x98, 0x63, 0xec, 0x6a, 0x88, 0x4b, 0x93, 0xc4, 0x8a, 0x30, 0x54,
								0x1c, 0x9b, 0x5a, 0xfb, 0x11, 0xcb, 0x92, 0x44, 0x96, 0xa8, 0x31, 0xa3, 0x84, 0xa1,
								0x7e, 0x54, 0xc6, 0x49, 0xe4, 0xfa, 0x62, 0xc4, 0xf4, 0x54, 0xea, 0x1b, 0x9c, 0x55,
								0xb5, 0x52, 0x17, 0x6, 0x17, 0x70, 0x76, 0x3a, 0x79, 0x61, 0xfc, 0x85, 0x15, 0xe,
								0xb3, 0x12, 0x5e, 0x6d, 0xb3, 0x97, 0x18, 0x56, 0x2c, 0x52, 0x30, 0x4e, 0x66, 0x81,
								0xe, 0xf3, 0x7c, 0x8a, 0x2a, 0x46, 0x93, 0x74, 0xd1, 0xa8, 0x77, 0x6b, 0x66, 0x5d,
								0x4d, 0x24, 0x29, 0x48, 0x0, 0x19, 0x83, 0xc9, 0xa3, 0x46, 0x86, 0xb, 0xf0, 0xba,
								0x14, 0x18, 0xc6, 0xbc, 0x1b, 0xb1, 0xdf, 0x7e, 0xf, 0x2b, 0x51, 0xcb, 0x22, 0xa0,
								0x61, 0x31, 0x50, 0x77, 0xe, 0x13, 0x84, 0xc7, 0x5c, 0xe6, 0xe2, 0x28, 0xcf, 0x83,
								0x4a, 0x41, 0xb2, 0x4b, 0x8c, 0x61, 0x72, 0x42, 0x53, 0x3c, 0x2a, 0x6a, 0xdc, 0x86,
								0x58, 0x83, 0xc7, 0x78, 0x44, 0x5c, 0x9b, 0x90, 0xc1, 0x12, 0xc6, 0x29, 0x70, 0x33,
								0xfe, 0xc2, 0x1e, 0x66, 0x6b, 0x11, 0x8, 0x1d, 0xd1, 0x74, 0xce, 0xe3, 0xa, 0x0, 0x6b,
								0xf2, 0xa2, 0x68, 0x7, 0xc1, 0xd, 0x72, 0xc0, 0xe6, 0x2b, 0xdc, 0x11, 0xfb, 0xeb, 0xef,
								0x70, 0x1f, 0x63, 0x1e, 0x23, 0x91, 0xdb, 0x41, 0x75, 0x53, 0x88, 0x38, 0xb8, 0xa5,
								0x1, 0xf7, 0x74, 0x12, 0x66, 0x48, 0x27, 0xe2, 0xf4, 0x1d, 0x65, 0x9, 0xe6, 0x83,
								0x34, 0x28, 0xe3, 0x91, 0x10, 0x9e, 0xa7, 0x42, 0xb, 0x4b, 0x12, 0xc7, 0x91, 0x30,
								0x10, 0x6e, 0x6d, 0xb3, 0xf4, 0x35, 0x48, 0xc6, 0x9d, 0x92, 0x6c, 0x54, 0x99, 0xe2,
								0x68, 0x43, 0x3a, 0x3a, 0x83, 0xb5, 0x6b, 0x2b, 0xfd, 0xe2, 0xd8, 0x60, 0xfa, 0xbd,
								0x9, 0xb6, 0x6b, 0xe4, 0x9e, 0xb8, 0x1f, 0xad, 0xa9, 0xab, 0x11, 0xdb, 0x43, 0x9d,
								0x20, 0x1b, 0xdf, 0x87, 0x98, 0xf3, 0x8a, 0x8f, 0x9b, 0x95, 0x29, 0xda, 0x9e, 0xb1,
								0xc2, 0x9a, 0xaa, 0xfd, 0xbd, 0xcb, 0x8e, 0xce, 0xce, 0xc2, 0x6f, 0xa8, 0x53, 0x50,
								0xa3, 0x79, 0x65, 0x8c, 0xff, 0x81, 0x4a, 0xfe, 0xc2, 0x41, 0xd6, 0x35, 0x5b, 0xdb,
								0x5a, 0x1f, 0xb9, 0x17, 0x46, 0x13, 0xc2, 0xe6, 0xf1, 0x1b, 0x18, 0xe, 0xd1, 0xda, 0x8,
								0x13, 0x6c, 0x48, 0x1c, 0xe2, 0xa6, 0x74, 0xac, 0x50, 0x4b, 0x84, 0x3d, 0xbd, 0xa0,
								0x80, 0x45, 0x7f, 0x1c, 0xb1, 0xe7, 0x40, 0x83, 0x65, 0x10, 0xab, 0x41, 0x28, 0xa1,
								0x29, 0x3d, 0x8a, 0x11, 0x9b, 0x70, 0xe5, 0x88, 0x2a, 0xf2, 0xc6, 0xb9, 0x17, 0xad,
								0x79, 0x6e, 0xbb, 0xe, 0x8f, 0x8d, 0x76, 0xc4, 0xfd, 0x6a, 0xb9, 0x69, 0xa7, 0xd2, 0xf4,
								0x1a, 0x9a, 0x69, 0xb8, 0xbf, 0xca, 0x92, 0xbb, 0x88, 0x5e, 0xb9, 0x5d, 0x9e, 0x7, 0xfa,
								0xa4, 0x8, 0xf1, 0x40, 0x52, 0xf8, 0x86, 0xfa, 0x6e, 0x78, 0x18, 0xc5, 0x9c, 0xd8, 0x15,
								0x37, 0x1c, 0x2e, 0x13, 0xa9, 0x32, 0x39, 0x57, 0xe1, 0x3d, 0xb, 0x2d, 0xbc, 0x41, 0x8e,
								0x17, 0xe8, 0x60, 0xc4, 0x7a, 0xcb, 0x93, 0x88, 0xf2, 0x3a, 0xe8, 0x7f, 0x4a, 0xd7,
								0x69, 0x83, 0x9, 0x1a, 0x34, 0xb1, 0x9f, 0x93, 0x79, 0x54, 0xcc, 0xa4, 0xe0, 0x8a, 0x5d,
								0x44, 0x16, 0x25, 0x57, 0x54, 0xfb, 0x16, 0xeb, 0x5d, 0x20, 0x36, 0xfe, 0x5a, 0x89,
								0xb9, 0xdd, 0xb2, 0xfe, 0x90, 0x94, 0x28, 0x23, 0xe, 0x95, 0x25, 0x8f, 0x4e, 0x6f, 0x62,
								0xe1, 0x17, 0x5a, 0xdf, 0x6b, 0xae, 0x30, 0x4c, 0x2c, 0x97, 0x93, 0x10, 0xd2, 0x88,
								0x72, 0x17, 0xa4, 0x5a, 0x2c, 0xab, 0xc2, 0xf2, 0x7e, 0xdc, 0x87, 0xd, 0x53, 0x82, 0x63,
								0x74, 0xf1, 0x54, 0xf3, 0xb8, 0xb, 0x7f, 0x3d, 0x68, 0x97, 0x53, 0xcf, 0x8f, 0x61, 0x36,
								0x33, 0x94, 0x36, 0xed, 0xfe, 0x4f, 0x3d, 0xa1, 0xd9, 0xec, 0xe0, 0x51, 0x13, 0x77,
								0x38, 0xee, 0x40, 0x8d, 0xd6, 0xb5, 0x3c, 0x7e, 0xd3, 0xa0, 0x84, 0xe0, 0xc1, 0x60,
								0x83, 0x0, 0x98, 0x4b, 0x6b, 0x34, 0xd9, 0xc8, 0xc5, 0xb1, 0x7, 0x11, 0xeb, 0x55, 0x13,
								0x60, 0xad, 0x28, 0xcf, 0x30, 0x60, 0x61, 0xff, 0x3, 0xfb, 0x73, 0xa9, 0x25, 0x39, 0x34,
								0xa5, 0xa4, 0xa4, 0x55, 0x10, 0xb, 0xfd, 0x35, 0xd7, 0xb7, 0x34, 0x59, 0xbb, 0x56, 0xeb,
								0xa8, 0x6d, 0x5c, 0xe1, 0xe2, 0xda, 0x47, 0xff, 0x10, 0x10, 0x75, 0x1a, 0xa3, 0x80,
								0xc2, 0x8b, 0x3f, 0x11, 0xa4, 0xf4, 0xbe, 0x24, 0x6, 0x5a, 0xe0, 0xa2, 0xe3, 0x76, 0x11,
								0xc6, 0x33, 0xd0, 0x2a, 0x4d, 0xd0, 0x1e, 0xc5, 0xa8, 0xb6, 0xb0, 0xdf, 0xd8, 0xf2,
								0x60, 0x9b, 0x9, 0xe2, 0x9a, 0xed, 0xac, 0x8c, 0xbd, 0x93, 0x36, 0x44, 0x4b, 0xb9, 0xf2,
								0x52, 0x5e, 0xd5, 0x21, 0x37, 0xca, 0xe6, 0xb9, 0x4, 0x35, 0x2a, 0xe2, 0xd9, 0xde, 0xf3,
								0x73, 0xd9, 0xa8, 0xf8, 0xe, 0x2d, 0xe6, 0x73, 0x6f, 0x24, 0xbc, 0xf6, 0xc6, 0xc1, 0xcd,
								0xd0, 0xe1, 0x83, 0xe9, 0x53, 0x4a, 0xfd, 0x2a, 0xb6, 0x11, 0x47, 0x2d, 0x4, 0x7, 0xfc,
								0x66, 0xed, 0x0, 0x49, 0x4a, 0xb5, 0xdd, 0x4e, 0x85, 0x3f, 0xbe, 0x78, 0xf3, 0x86, 0xfe,
								0x51, 0x79, 0x1f, 0x42, 0xf3, 0x42, 0x40, 0x9, 0x84, 0x29, 0xfa, 0xd, 0xa5, 0x28, 0xf1,
								0x8e, 0x68, 0xe7, 0x81, 0xff, 0xfd, 0x98, 0x89, 0xc6, 0x58, 0x77, 0x29, 0x68, 0x4b,
								0x36, 0x36, 0x96, 0x2f, 0x6f, 0x14, 0x15, 0xc1, 0x58, 0xcf, 0x10, 0xe3, 0x9, 0x9f, 0x4c,
								0xe0, 0x35, 0xbf, 0x8, 0xaf, 0xbf, 0x75, 0x77, 0xef, 0xa0, 0x83, 0xe, 0x3a, 0xe8, 0xa0,
								0x83, 0xe, 0x3a, 0xe8, 0xa0, 0x83, 0xe, 0x3a, 0xe8, 0xa0, 0x83, 0xe, 0x3a, 0xd8, 0xda,
								0xfa, 0x17, 0xe2, 0x8a, 0xf9, 0x39, 0x0, 0x28, 0x0, 0x0,
							},
						},
					},
				},
			},
		},
		{
			name: "nope.tgz",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/nope.tgz",
			want:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer func() {
				_ = f.Close()
			}()

			info, err := os.Stat(tt.inputFile)
			require.NoError(t, err)

			a := helmConfigAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Info:     info,
				Content:  f,
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_helmConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "yaml",
			filePath: "testdata/testchart/Chart.yaml",
			want:     true,
		},
		{
			name:     "tpl",
			filePath: "testdata/testchart/templates/_helpers.tpl",
			want:     true,
		},
		{
			name:     "json",
			filePath: "testdata/testchart/values.yaml",
			want:     true,
		},
		{
			name:     "NOTES.txt",
			filePath: "testdata/testchart/templates/NOTES.txt",
			want:     false,
		},
		{
			name:     ".helmignore",
			filePath: "testdata/testchart/.helmignore",
			want:     true,
		},
		{
			name:     "testchart.tgz",
			filePath: "testdata/testchart.tgz",
			want:     true,
		},
		{
			name:     "testchart.tar.gz",
			filePath: "testdata/testchart.tar.gz",
			want:     true,
		},
		{
			name:     "nope.tgz",
			filePath: "testdata/nope.tgz",
			want:     true, // its a tarball after all
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := helmConfigAnalyzer{}

			info, _ := os.Stat(tt.filePath)

			got := s.Required(tt.filePath, info)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_helmConfigAnalyzer_Type(t *testing.T) {
	s := helmConfigAnalyzer{}

	want := analyzer.TypeHelm
	got := s.Type()
	assert.Equal(t, want, got)
}
