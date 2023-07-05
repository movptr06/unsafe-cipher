#!/usr/bin/env python3

import random

P = 30339589087763868522478011113126411244280269878582076318386089105964369982916454160571926466871800477751103846116310567032049165253551555881148469519616796493443755080039874877131550333224584503656733010931392839412364892852031630918801908581838785086570189759640227800709257644921396554624520292824090030188037205114735222701392125537072140916249035217495352611350435518600868751752227799379183219938825717208337967144618125258153873963470238793984938299560973519262389056163256873120106913050450220112504182540794475291212343695771362452674990464595556602037699784825192575310597137071008023035849498210154426513913 

MAX = 115792089237316195423570985008687907853269984665640564039457584007913129639935

def dh_keygen():
    private = random.randint(1, MAX)
    public = pow(2, private, P)
    return private, public

def dh_getkey(private, public):
    K = pow(public, private, P)
    K = K.to_bytes(256, byteorder="little")
    return K
