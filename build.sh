#!/bin/bash
# To build, either place the IPA file in the project's root directory, or get the path to the IPA, then run `./build.sh`

read -r -p $'\e[34m==> \e[1;39mPath to the decrypted YouTube.ipa or YouTube.app. If nothing is provided, any ipa/app in the project\'s root directory will be used: ' PATHTOYT

# Check if PATHTOYT is empty
if [ -z "$PATHTOYT" ]; then
    # Keep paths intact (including whitespace/newlines) and do not follow symlinks.
    CANDIDATES=()
    while IFS= read -r -d '' CANDIDATE; do
        CANDIDATES+=("$CANDIDATE")
    done < <(find . -maxdepth 1 \( -type f -name "*.ipa" -o -type d -name "*.app" \) -print0)

    COUNT=${#CANDIDATES[@]}

    if [ "$COUNT" -ge 2 ]; then
        echo "❌ Error: Multiple IPA/app candidates found in the project's root directory. Make sure there is only one."
        exit 1

    elif [ "$COUNT" -eq 1 ]; then
        PATHTOYT=${CANDIDATES[0]}

    else
        echo "❌ Error: No IPA/app file found in the project's root directory directory."
        exit 1
    fi
fi

make package THEOS_PACKAGE_SCHEME=rootless IPA="$PATHTOYT" FINALPACKAGE=1

# SHASUM
if [[ $? -eq 0 ]]; then
  open packages
  echo "SHASUM256: $(shasum -a 256 packages/*.ipa)"

else
  echo "Failed building uYouPlus"

fi
