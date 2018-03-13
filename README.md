<img src='https://i.imgur.com/IwgWrHA.png' />

Its just a prototype of a WAF core which makes of mathematical algorithms to determine if the input is malicious.

#### Detection Methods
- Entropy
- Shannon Entropy
- Levenshtein Distance
- Special Character Ratio
- Some regex (I don't think its necessary but still...)

### How it works?
**Entropy** gets it name from a scientific term "Entropy".
> Entropy is basically the measure of randomness of something

But how does it apply to detection of malicious payloads?</br>
Take a look at these two strings and their entropy
```
String: black pens & red caps
Entropy: 0.000302964443769

String: <svg onload=alert()>
Entropy: 53.4044125463
```
Does it make sense now?<br>
Let me introduce you to all the algorithms used now

##### Entropy
```
log(score)/log(2)) * len(payload)
```
Where score is the number of special characters in the string.<br>
Entropy increases with increase in search space.

##### Shannon Entropy
```
for number in range(256):
    result = float(payload.count(chr(number)))/len(payload)
    if result != 0:
        entropy = entropy - result * log(result, 2)
```
For a better understanding take a look the source code.<br>
But what shannon entropies does is that considers patterns too.<br>
Take a look at these three strings and their shannon entropies:
```
String: s0md3v
Entropy: 2.58496250072

String: ../../../../
Entropy: 0.918295834054

String: //////////////
Entropy: 0.0
```
The first string has no repeating pattern and hence has the highest value of shannon entropy while the second string however has a repeating pattern which lowers it entropy to nearly one. The last string only consists a single character and has no randomness and hence has 0 shannon entropy.

##### Special Char ratio
```
(len(payload) - score) <= len(payload)/2
```
Where score is again the number of special characters in the string.<br>
We are just checking if the string's 50% part or more is made of special characters.

##### Levenshtein Distance
Most of the WAFs check if the input matches a regex or payload in their signature database. But instead of looking for same payloads in signature database, <b>Entropy</b> looks for *similar* payloads using Levenshtein Distance algorithm.
Instead of reinventing the wheel and writing the algorithm myself, I used <b>FuzzyWuzzy</b> module but when this project will be further developed, I may use my own code.

Thats all folks.

#### License & Other Stuff
This project has no license and in that case, according to international standards you are not allowed to modify or redistribute it but as its hosted on Github, you are free to view and use the code ;)<br>
Do you think this is a great idea? Do you know something which can make it better? Mail me at s0md3v(at)gmail(dot)com
