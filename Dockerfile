# Multi-stage build for the admitly webhook. Not built or published by this
# repository's CI; provided so deploy/admitly.yaml has a matching image recipe.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/admitly ./cmd/admitly

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/admitly /admitly
USER 65532:65532
ENTRYPOINT ["/admitly"]
