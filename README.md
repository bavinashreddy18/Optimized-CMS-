# Identification of Heavy Hitters using Optimized CMS SKETCH 
Inspired from Gated-Sketch Theory and optimized Count min Sketch for detection of Heavy Hitters in p4. 
In Check.p4, its main P4 pipeline of logic based on Threshold of individual state and enters next state rather CMS uses overall threshold at end state. This makes to calculate the count for every state and makes high complex. Whereas this method out performs the CMS usage.
