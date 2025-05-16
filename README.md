# VanitySearch-Bitrack with Optimization for BTC Puzzle 

# Feature

<ul>
  <li>Optimized CUDA modular math for better performance (6900 MKeys/s on 4090, 8800 MKeys/s on 5090).</li>
  <li>Less RAM usage.</li>
  <li>Starting key setting function optimized with Ecc addition and batch modular inverse.</li>
  <li>Easier definition of the range to scan by defining it as a power of 2.</li>
  <li>Only 1 GPU allowed for better efficiency.</li>
  <li>Only compressed addresses and prefixes.</li>
  <li>Pressing "p" it is possibile to pause vanitysearch freeing the GPU, press again "p" to resume.</li>
  <li>Added prefix search. Be careful to -m parameter.</li>
  <li>NEW: Added Random mode. Each GPU thread scans 1024 consecutive random keys at each step.</li>
  <li>NEW: Added backup mode. Approximately every 60 seconds, an automatic backup file is created for each GPU, containing information about the progress made in the last sequential search.
This makes it possible, by using the "-backup" option, to resume the sequential search while keeping the progress from the last session.
This is useful in case the program closes for any reason.</li>

</ul>

# Usage


VanitySeacrh [-v] [-gpuId] [-i inputfile] [-o outputfile] [-start HEX] [-range] [-m] [-stop]

 -v: Print version
 
 -i inputfile: Get list of addresses/prefixes to search from specified file
 
 -o outputfile: Output results to the specified file
 
 -gpuId: GPU to use, default is 0
 
 -start start Private Key HEX
 
 -range bit range dimension. start -> (start + 2^range)

 -m: Max number of prefixes found by each kernel call, default is 262144 (use multiples of 65536)

 -stop: Stop when all prefixes are found

 -random: Random mode active. Each GPU thread scan 1024 random sequentally keys at each step. Not active by default

 -backup: Backup mode allows resuming from the progress percentage of the last sequential search. It does not work with random mode.


If you want to search for multiple addresses or prefixes, insert them into the input file.

Be careful, if you are looking for multiple prefixes, it may be necessary to increase MaxFound using "-m". Use multiples of 65536. The speed might decrease slightly.

In Random mode each thread selects a random number within its subrange and scans 512 keys forward and 512 keys backward. Random mode has no memory; the higher the percentage of the range that is scanned, the greater the probability that already scanned keys will be scanned again.

----------------------------------------------------------------------------

Donations are always welcome! :) bc1qag46ashuyatndd05s0aqeq9d6495c29fjezj09

# Exemples:

Windows:


```./VanitySearch.exe -gpuId 0 -i input.txt -o output.txt -start 3BA89530000000000 -range 40```

```./VanitySearch.exe -gpuId 1 -o output.txt -start 3BA89530000000000 -range 42 1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ```

```./VanitySearch.exe -gpuId 0 -start 3BA89530000000000 -range 41 1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ ```

```./VanitySearch.exe -gpuId 0 -start 100000000000000000 -range 68 -random 19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG```

```./VanitySearch.exe -gpuId 0 -start 3BA89530000000000 -range 41 -backup 1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ ```

Linux

```./vanitysearch -gpuId 0 -i input.txt -o output.txt -start 3BA89530000000000 -range 40```


# License

VanitySearch is licensed under GPLv3.



