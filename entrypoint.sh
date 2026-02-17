#!/bin/sh -e

#TODO: Consider allowing for non-2FA. Seems really insecure as the full credentials would linger in the container. Then again it's hardly secure anyway there's no access token expiry afaik.
#TODO: Better handling of existing but invalid access tokens. For now we blanket use existing as otherwise container restarts would attempt to auth using stale 2FA token and fail. The downside of this is when we have an expired access token we need to manually remove it to trigger retrieval of a new access token.

# If access token already exists, simply start serving.
if [ ! -f ~/.config/ferroxide/auth.json ]; then

  if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    printf "Incorrect argument count.\n"
    printf "Please provide:\n1) Username\n2) Password\n3) Two factor token\n"
    exit 1
  fi

  # If a token was provided, it must be 6 digits. Otherwise, proceed without 2FA.
  if [ $# -eq 3 ] && [ -n "${3}" ]; then
    if [ ${#3} -ne 6 ]; then
      printf "Two factor auth token is not the correct length. Exiting.\n"
      exit 3
    fi

    printf "%s\n%s\n" "${2}" "${3}" | ./ferroxide auth "${1}"
  else
    printf "%s\n" "${2}" | ./ferroxide auth "${1}"
  fi

  if [ $? -ne 0 ]; then
    printf "Authentication failed. Exiting.\n"
    exit 2
  fi

  printf "Authentication successful.\n"

fi

./ferroxide serve
