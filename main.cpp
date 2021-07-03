#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

void SensorCorRGB(int *R, int *G, int *B){
    int a = rand() % 3;
    *R = 0; *G = 0; *B = 0;
    switch(a)
    {
        case 1: *R = rand() % 255;
        case 2: *G = rand() % 255;
        case 3: *B = rand() % 255;
    }
}

void CapCoresRGB(int *Cor){

    int CorR, CorG, CorB;
    SensorCorRGB(&CorR, &CorG, &CorB);
    if(CorR > 0){*Cor = CorR;}
    if(CorG > 0){*Cor = CorG;}
    if(CorB > 0){*Cor = CorB;}
}

int main(){

    int Cor;
    int y=500, x=500;
    unsigned int MatRGB[2][y][x];

     for(y=1; y <= 500; y++){
         for(x=1; x <= 500; x++){
             CapCoresRGB( &Cor); MatRGB[0][y][x] = Cor;
             CapCoresRGB( &Cor); MatRGB[1][y][x] = Cor;
             CapCoresRGB( &Cor); MatRGB[2][y][x] = Cor;
             printf(" %d%d%d", MatRGB[0][y][x], MatRGB[1][y][x], MatRGB[2][y][x]);
         }
         printf("\n");
     }
     printf("Fim\n");
     system("pause");

}
