#!/bin/sh

case "$1" in
  *Username*) printf '%s\n' "$GITEA_PAGES_GIT_TOKEN" ;;
  *) printf '\n' ;;
esac
