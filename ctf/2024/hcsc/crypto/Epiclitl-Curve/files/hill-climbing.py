import math
import random

def solutionFitness(sol):
    a = float(sol[0])
    b = float(sol[1])
    c = float(sol[2])
    if((a+b == 0)or(a+c==0)or(b+c==0)):
        return 10000000
    output = a/(b+c)+b/(c+a)+c/(a+b)-10
    output = output*output
    return output

def modSolution(sol):
    a = sol[0]
    b = sol[1]
    c = sol[2]
    idx = random.randint(0,2)
    val = random.randint(-1000,1000)
    output = [a,b,c]
    output[idx] = val
    return output

def generateSolution():
    a =  random.randint(-1000,1000)
    b =  random.randint(-1000,1000)
    c =  random.randint(-1000,1000)
    return [a,b,c]

bestSol = generateSolution()
bestFit = solutionFitness(bestSol)
start_over = False
count = 0
while bestFit != 0.0:
    currentSol =  modSolution(bestSol)
    currentFit = solutionFitness(currentSol)
    count += 1
    if currentFit < bestFit:
        bestSol = currentSol
        bestFit = currentFit
        count = 0
    if count > 1000:
        start_over = True
    if start_over == True:
        bestSol = generateSolution()
        bestFit = solutionFitness(bestSol)
        start_over = False
        count = 0
print(bestSol)