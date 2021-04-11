# integritychecker

Correct order of running commands:


javac -XDignore.symbol.file Files.java Ichecker.java

java Ichecker createCert -k private.key -c pub.crt

java Ichecker createReg -r reg.txt -p path -l log.txt -h SHA-256 -k private.key

java Ichecker check -r reg.txt -p path -l log.txt -h SHA-256 -c pub.crt






