# known key bruteforcer
This little rust projects bruteforces the ~/.ssh/known_hosts file with incredible speed.

# Build

To use this repo you must build the project with the release flag or use the
`build.sh`.

(The normal build performance is significant slower 1/100 of the release speed)

# Usage

Due to the high parallelization and cpu time it's advised to only assign (CPU-Core -1)
threads for the bruteforcer or the system may not respond anymore.

```
Usage example: ./known-key-bruteforcer -f /home/root/.ssh/known_hosts -t 7 -s 65.0.0.0 -e 66.0.0.0
 -f known_hosts file to bruteforce   (Default $Home/.ssh/known_hosts)
 -t Thread count for the bruteforcer (Default 1)
 -s Start of ip range                (Default 0.0.0.1)
 -e End of ip range                  (Default 0.0.0.200)
 -h Help
```

# Contribute

If any of you rust savvy people find a performance tweak pleas let me know :)