# Enumeration
Script for automating enumeration process

## Single Domain
```
# Results will land under $PWD/results on your host
docker run --rm -it \
  -v "$PWD/results:/work/results" \
  -v "$HOME/.config/subfinder:/root/.config/subfinder" \
  lazyrecon-plus:latest \
  -d example.com
```

## Scope from file
```
docker run --rm -it \
  -v "$PWD:/work" \
  -v "$HOME/.config/subfinder:/root/.config/subfinder" \
  -e THREADS=50 -e NUCLEI_RATE=200 \
  lazyrecon-plus:latest \
  -l /work/scope.txt --gh-org your-github-org
```
