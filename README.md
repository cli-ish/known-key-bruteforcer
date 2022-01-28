# known key bruteforcer

This little rust projects bruteforces the ~/.ssh/known_hosts file with incredible speed.

Idea of this project came from this perl implementation which was too slow for my taste:
https://github.com/xme/known_hosts_bruteforcer

In a Test setup with a AMD Ryzen 7 5800X 8-Core Processor we got with 11 threads a performance of 308000 Hashes per ms which equals to 308 MH/s
A Test with 28 Hashes was done in 45 minutes (1.0.0.0 to 254.255.255.255) and found all valid hash combos.

If more speed is required its advised to use hashcat with a stronger cpu like this repos suggests https://github.com/chris408/known_hosts-hashcat

# Get or Build

Can be pulled directly from the v1.0.0
release https://github.com/cli-ish/known-key-bruteforcer/releases/tag/v1.0.0

To build this repo you must build the project with the release flag or use the
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
