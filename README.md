## Demo Java Service

Demo Java Service initialized using Spring Initializr from https://start.spring.io/.
Created to showcase the issue with false positives reported by [NeuVector Scanner](https://github.com/neuvector/scanner).

`/neuvector-scanner-patch` contains potential patch for NeuVector Scanner fix to address the issue with false positives report.
`/neuvector-scanner-patch/README.md` contains detailed explanation of the patch and the root cause for false positives.

## How to reproduce the issue locally

1. Build the Docker image for the service:
   ```
   docker build -t demo-java-service .
   ```
2. Run NeuVector scanner using latest version using podman/docker command
   ```
   podman run --rm -v /run/podman/podman.sock:/var/run/docker.sock -v $(pwd):/results --security-opt label=disable neuvector/scanner:latest -i localhost/demo-java-service:latest
  ```
3. Observe the results and verify that the false positives are reported.
4. Apply the patch from `/neuvector-scanner-patch` to the upstream https://github.com/neuvector/scanner and recheck using patched scanner.
