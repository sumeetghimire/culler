FROM scratch
COPY culler /culler
ENTRYPOINT ["/culler"]
