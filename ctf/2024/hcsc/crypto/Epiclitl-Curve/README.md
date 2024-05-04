# HCSC 2024 - Epiclit'l' Curve

## Description

Élek, halok a középiskolás matekért! Három változó, egy konstans és egyetlen képlet. Mi kell még?

Sok sikert hozzá! **A forrást csatoltuk!**

Készítői kommentek:
* a megoldáshoz szerver oldali brute-force nem szükséges
* amennyiben lehetséges, kérjük ne a szerveroldalt terheld, hacsak nem úgy érzed, hogy közel állsz a megoldáshoz
* VPN kapcsolat szükséges
* A jelenlegi `challenge.zip` sha256sum hash-e: `5bb888194a2a220d3ae796723550d48598eb05da7c0dfcd820ca2d64f4016b12`
* a challenge egyetlen porton fut

**Flag formátum**: `HCSC24{...}`

*By MJ*

> Hint 1 (cost 250): Find the paper! https://i.imgur.com/XN2sGWp.png

## Metadata

- Tags: `Diophantine equation`, `sage`, `elliptic curve`
- Points: `500`
- Number of solvers: `35`
- Filename: [`challenge.zip`](files/challenge.zip)

## Solution

The challenge was running on `10.10.(1-9).12:49428`. Let's connect to the server first with `nc`:

```
$ nc 10.10.1.12 49428
I got a simple challenge for you! You are in control of x, y, and z. They need to be positive integers with at most 200 digits. Supply some values that satisfy the following equation:

x/(y+z) + y/(x+z) + z/(x+y) = 10
\frac{x}{y+z} + \frac{y}{x+z} + \frac{z}{x+y} = 10 (the same, but in LaTeX format)

We would appreciate if you wouldn't DoS the public instance with a high number of connections or requests. The source is provided for you to run your own instance.

You have 30 seconds to send your answer. Good luck!

Enter the value for x:
```

We have to solve `x/(y+z) + y/(x+z) + z/(x+y) = 10` so that `x`, `y` and `z` are positive integers.

If we lucky enough, we find the following link which gives the solution: <https://math.stackexchange.com/questions/402537/find-integer-in-the-form-fracabc-fracbca-fraccab/409450#409450>

```
a=221855981602380704196804518854316541759883857932028285581812549404634844243737502744011549757448453135493556098964216532950604590733853450272184987603430882682754171300742698179931849310347
b=269103113846520710198086599018316928810831097261381335767926880507079911347095440987749703663156874995907158014866846058485318408629957749519665987782327830143454337518378955846463785600977
c=4862378745380642626737318101484977637219057323564658907686653339599714454790559130946320953938197181210525554039710122136086190642013402927952831079021210585653078786813279351784906397934209
```

If we are not lucky enough we can definitely find the following page: <https://www.quora.com/How-do-you-find-the-positive-integer-solutions-to-frac-x-y+z-+-frac-y-z+x-+-frac-z-x+y-4>

To be honest I did not want to really get into the math part and understand it because I was sure that there is someone who already solved the problem. I didn't want to reinvent the wheel.

It turned out that we first need a solution for the equation with integers (but some of them can be negative). I found a script with a hillclimbing algorithm to find a solution ([`hill-climbing.py`](files/hill-climbing.py)):
- <https://news.ycombinator.com/item?id=14943528>
- <http://codepad.org/PixRUl0N>

```python
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
```

The script finds `[-336,912,432]` as one solution.

Let's modify the `MAGMA` code found in the Quora article (second comment, by `Eduardo Ruiz`) to solve our problem ([`solution.magma`](files/solution.magma)):

```magma
// http://magma.maths.usyd.edu.au/calc/ 
// Eduardo Ruiz Duarte  
// toorandom@gmail.com 

// First we define our environment for our "problem" 
R<x,y,z> := RationalFunctionField(Rationals(),3); 
problem := ((x/(y+z) + y/(x+z) + z/(x+y)) - 10) ; 
// First note that we know a point after some computation (-336,912,432) that works but has a negative coordinate, the following function returns 0, which means that (x/(y+z) + y/(x+z) + z/(x+y)) - 10 = 0 (just put the -10 in the other side) 
Evaluate(problem,[-336,912,432]); 
 
// After the previous returned 0, we know the point fits, we continue. 
// We multiply by all the denominators of "problem" to get a polynomials problem*Denominator(problem); 
// We obtain a polynomial without denominators x^3 - 9*x^2*y - 9*x^2*z - 9*x*y^2 - 17*x*y*z - 9*x*z^2 + y^3 - 9*y^2*z - 9*y*z^2 + z^3 
// We see it is cubic, three variables, and every term has the same degree (3), therefore this is a cubic homogeneous curve, we know there is a point which is not the solution we want the point (-336,912,432) fits in the original "problem" so it should fit in this new curve without denominators too (since no denominator becomes 0) we transform this equation to a "curve" in Projecive space of dimension 2 
P2<x,y,z> := ProjectiveSpace(Rationals(),2); 
C := Curve(P2,x^3 - 9*x^2*y - 9*x^2*z - 9*x*y^2 - 17*x*y*z - 9*x*z^2 + y^3 - 9*y^2*z - 9*y*z^2 + z^3); 
 
// Fit the point to the curve C (no error is returned) 
Pt := C![-336,912,432]; 
 
// Since all cubic homogeneous curve with at least one point define an elliptc curve, we can transform  this curve C to an elliptc curve form and just like in cryptography, we will add this known point (mapped to the corresponded curve) with itself until we get only positive coordinates and go back to C (original Problem) 
// Below, E is the curve, f is the map that maps   Points f:C -> E  (C is our original curve without denominators, both curves C,E are equivalent but in E we can "Add points" to get another point of E, and with f^-1 we can return to the point of C which is our original solution 
E,f := EllipticCurve(C); 
 
// g is the inverse g:E->C, f:C->E so g(f([-336,912,432]))=[-336,912,432] 
g := f^-1; 
 
// We try adding the known point Pt=[-336,912,432] mapped to E, 2..100 times to see if when mapped back the added point to C gives positive coordinates, this is 2*Pt, 3*Pt, ...., 100*Pt  and then mapping back to C all these. 
for n:= 1 to 100 do 
    // We calculate n times the point of C, known [-336,912,432] but mapped (via f) inside E (where we can do the "n times")  
    nPt_inE:=n*f(Pt); 
    
    // We take this point on E back to C via f^-1  (which we renamed as g) 
    nPt_inC:=g(nPt_inE); 
 
    // We obtain each coordinate of this point to see if is our positive solution, here MAGMA scales automatically the point such as Z is one always 1, so it puts the same denominators in X,Y, so numerators of X,Y are our solutions and denominator our Z, think of  P=(a/c,b/c,1)   then c*P=(a,b,c) 
    X := Numerator(nPt_inC[1]); 
    Y := Numerator(nPt_inC[2]); 
    Z := Denominator(nPt_inC[1]); 
 
    printf "X=%o\nY=%o\nZ=%o\n",X,Y,Z; 
 
    // We check the condition for our original problem. 
    if ((X gt 0) and (Y gt 0)) then 
        printf("GOT IT!!! x=apple, y=banana, z=pineapple, check the above solution\n"); 
        break; 
    else 
        printf "Nee, some coordinate was negative above, I keep in the loop\n\n"; 
    end if; 
end for;    
 
// We check the solution fits in the original problem 
if Evaluate(problem, [X,Y,Z]) eq 0 then 
    printf "I evaluated the point to the original problem and yes, it worked!\n"; 
else 
    printf "Mmm this cannot happen!\n"; 
end if; 
```

Let's run the modified code in a MAGMA calculator: <http://magma.maths.usyd.edu.au/calc/>

```
X=-7
Y=19
Z=9
Nee, some coordinate was negative above, I keep in the loop

X=34783
Y=-33111
Z=26720
Nee, some coordinate was negative above, I keep in the loop

X=-19044137259
Y=-18258545377
Z=15014826703
Nee, some coordinate was negative above, I keep in the loop

X=-978195939931447769
Y=1018634508366092864
Z=889491528529367049
Nee, some coordinate was negative above, I keep in the loop

X=16222545140743978153264639681
Y=-8606669587670748111150842127
Z=10418211329473954994210412443
Nee, some coordinate was negative above, I keep in the loop

X=-24261409310017682876044896776256651556128
Y=-5958318438965947953007964082901677056135
Z=23770957725334064956892224069482132548591
Nee, some coordinate was negative above, I keep in the loop

X=3426953541995125369690545549718961912894160466925904697
Y=-2133992350362457262258437177484348308296997313016373789
Z=12680786662137812420835229172827896282441218272107717801
Nee, some coordinate was negative above, I keep in the loop

X=-417388010585522249486381806253050106441372949613896475468080599927307535
Y=-661007625332993769394326397853062486024490090654827255355891296856109201
Z=630510652275988853107313606974767620622215368381593706578802094432672896
Nee, some coordinate was negative above, I keep in the loop

X=-7959709895109709246560451288752583623166880928543622402176602802891291605823115743313778493
Y=10868158187777756527054952624718296879797481603429700907236704068832430644452186492363118681
Z=9483936591308699181636357255058738082124441792895760787983238980071485552383198854264983241
Nee, some coordinate was negative above, I keep in the loop

X=15783379648900073936942703293108596181126873045967074085926249392024788046536643574323457505708133669188013677223
Y=-16152182111025731117492523652561603949779429376711330533537787451834049438359495704727930359280334258915774084576
Z=16438763770535501925962909325336008663605074471307120175423630584550408732686071723992460682140366551652605968305
Nee, some coordinate was negative above, I keep in the loop

X=-6044156399364384742874406992392800150174798939409178151701234884493961915079718201513259802384010602507361502213363817677365119783370321
Y=-7808601155820568023234812899823105083906105581584974523152133220715948574285865915860385708387641786088544727347181924812548720149134113
Z=5085734336383678750291188748412434541896628335319852825316772886422890586502116170837839221833610501756117531251659488555886098203087557
Nee, some coordinate was negative above, I keep in the loop

X=-325491089253823735236132656390825730551331915995489020613103856456603634562039305478106746042301873466915794380143932838076680367987591336778224415702063353196224
Y=337834785599349493455089383955505744168628092965553264402858169393048917817982736702011374439154258249768388547262950467567720865585923472032297130816388125157959
Z=156202769236390628152194984765961992026116190808984946008913646152931264294304274989987662819572949607175414632134026979957500392489078897852211926824330252104489
Nee, some coordinate was negative above, I keep in the loop

X=4862378745380642626737318101484977637219057323564658907686653339599714454790559130946320953938197181210525554039710122136086190642013402927952831079021210585653078786813279351784906397934209
Y=221855981602380704196804518854316541759883857932028285581812549404634844243737502744011549757448453135493556098964216532950604590733853450272184987603430882682754171300742698179931849310347
Z=269103113846520710198086599018316928810831097261381335767926880507079911347095440987749703663156874995907158014866846058485318408629957749519665987782327830143454337518378955846463785600977
GOT IT!!! x=apple, y=banana, z=pineapple, check the above solution
I evaluated the point to the original problem and yes, it worked!
```

Let's input give numbers to the backend server:

```
$ nc 10.10.5.12 49428                
I got a simple challenge for you! You are in control of x, y, and z. They need to be positive integers with at most 200 digits. Supply some values that satisfy the following equation:

x/(y+z) + y/(x+z) + z/(x+y) = 10
\frac{x}{y+z} + \frac{y}{x+z} + \frac{z}{x+y} = 10 (the same, but in LaTeX format)

We would appreciate if you wouldn't DoS the public instance with a high number of connections or requests. The source is provided for you to run your own instance.

You have 30 seconds to send your answer. Good luck!

Enter the value for x: 4862378745380642626737318101484977637219057323564658907686653339599714454790559130946320953938197181210525554039710122136086190642013402927952831079021210585653078786813279351784906397934209
Enter the value for y: 221855981602380704196804518854316541759883857932028285581812549404634844243737502744011549757448453135493556098964216532950604590733853450272184987603430882682754171300742698179931849310347
Enter the value for z: 269103113846520710198086599018316928810831097261381335767926880507079911347095440987749703663156874995907158014866846058485318408629957749519665987782327830143454337518378955846463785600977


Congratulations! You somehow found a possible answer to an almost impossible equation.

All credits go to these amazing people, who figured out the hard math and made it possible for me to understand this problem:
- http://publikacio.uni-eszterhazy.hu/2858/1/AMI_43_from29to41.pdf
- https://www.quora.com/How-do-you-find-the-positive-integer-solutions-to-frac-x-y+z-+-frac-y-z+x-+-frac-z-x+y-4
- https://mathoverflow.net/a/227722
- https://www.youtube.com/watch?v=Ct3lCfgJV_A
- https://www.simonsfoundation.org/event/from-moonshine-to-black-holes-number-theory-in-mathematics-and-physics/ (from roughly 20m to 26m)

Flag: HCSC24{IF_l1f3_g1v3s_y0u_4_b4n4n4_3qu4t10n_y0u_sh0uld_s0lv3_1t}
```

Solution by `fadedave / dave` by implementing a `limit` function:

```python
# fadedave / dave
x,y,z = 1000,51,51
nx,ny,nz = x,y,z

for i in range(10000000):
    if abs(x/(y+z) + y/(x+z) + z/(x+y) - 10) < abs(nx/(ny+nz) + ny/(nx+nz) + nz/(nx+ny) - 10):
        x *= 10; y *= 10; z *= 10
        nx,ny,nz = x,y,z
    elif nx/(ny+nz) + ny/(nx+nz) + nz/(nx+ny) < 10:
        y,z = ny,nz
        ny-=1; nz-=1
    elif nx/(ny+nz) + ny/(nx+nz) + nz/(nx+ny) > 10:
        y,z = ny,nz
        ny+=1; nz+=1
print(x,y,z)
```

Solution by `alex_hcsc / alex1337` in `sagemath` (the concept is similar to mine):

```python
R.<x,y,z> = QQ[]
F = x^3 + y^3 + z^3 - 9*x^2*(y+z) - 9*y^2*(z+x) - 9*z^2*(x+y) - 17*x*y*z
E = EllipticCurve_from_cubic(F, morphism=True)

# Relative prime solutions
P = E([-7, 19, 9]) 
E.inverse()(P)

# Multiply manually, until we get the solution
E.inverse()(P*13)
(4862378745380642626737318101484977637219057323564658907686653339599714454790559130946320953938197181210525554039710122136086190642013402927952831079021210585653078786813279351784906397934209/269103113846520710198086599018316928810831097261381335767926880507079911347095440987749703663156874995907158014866846058485318408629957749519665987782327830143454337518378955846463785600977 : 221855981602380704196804518854316541759883857932028285581812549404634844243737502744011549757448453135493556098964216532950604590733853450272184987603430882682754171300742698179931849310347/269103113846520710198086599018316928810831097261381335767926880507079911347095440987749703663156874995907158014866846058485318408629957749519665987782327830143454337518378955846463785600977 : 1)
# Multiply it with 269103113846520710198086599018316928810831097261381335767926880507079911347095440987749703663156874995907158014866846058485318408629957749519665987782327830143454337518378955846463785600977 to get the solution
```

Solution by `Kamee Kaze` in `sagemath` (the concept is similar to mine):

```python
N = 10
e = (4*(N^2)) + ((12*N)-3)
f = 32*(N+3)
eq = EllipticCurve([0,e,0,f,0]) # Define the elliptic curve corresponding to the equation a/(b+c)+b/(a+c)+c/(a+b)=N
eq.rank()
print(eq.gens())
P = eq(-416,4160) # This is a generator for the group of rational points from ee.gens() result
def orig(P,N):
    x = P[0]
    y = P[1]
    a = (8*(N+3)-x+y)/(2*(N+3)*(4-x))
    b = (8*(N+3)-x-y)/(2*(N+3)*(4-x))
    c = (-4*(N+3)-(N+2)*x)/((N+3)*(4-x))
    da = denominator(a)
    db = denominator(b)
    dc = denominator(c)
    l=lcm(da,lcm(db,dc))
    return [a*l,b*l,c*l]
orig(P,N)
m = 13 # The smallest integer m such that one of the points mP + T, T ∈ Tor(EN(Q))
u = orig(m*P,N) 
(a,b,c) = (u[0],u[1],u[2])
print(a)
print(b)
print(c)
```

The official write-up by `MJ` is available at: <https://github.com/NIK-SOC/hcsc_2024_mj/tree/main/ctf-epiclitl_curve>

Flag: `HCSC24{IF_l1f3_g1v3s_y0u_4_b4n4n4_3qu4t10n_y0u_sh0uld_s0lv3_1t}`