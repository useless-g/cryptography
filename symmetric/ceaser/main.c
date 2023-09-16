    #include <stdio.h>
    #include <stdlib.h>
    #include <windows.h>

    int counter(FILE* File, int *pKey);

    int decypher(int Key, FILE *f);

    int main()
    {
        int Key = 0;
        int *pKey = &Key;
        FILE* File=0;
        char Filename[MAX_PATH];

        while (File == NULL)
        {
            if ((printf("Input correct path to the file 1: \n\r")) < 0)
            {
                printf("error of path 1");
                return 1;
            }
            if ((fgets(Filename, MAX_PATH, stdin)) == NULL)
            {
                printf("error");
                return 2;
            }
            Filename[strlen(Filename)-1] = '\0';

            if ((File = fopen(Filename, "r")) == NULL)
                printf("Error: incorrect path1. \n\r");
        }

        if(counter(File, pKey) != 0)
            return 3;

        if(fseek(File, SEEK_SET, 0) != 0)
        {
            printf("Error in fseek\n\r");
            return 4;
        }

        if(decypher(Key, File) != 0)
            return 5;

        if (fclose(File) != 0)
             {
                printf("Error in fclose\n\r");
                return 6;
             }
        return 0;
    }

    int counter(FILE* File, int *pKey)
    {
        if(File == NULL)
        {
            printf("Error2 in counter\n\r");
            return 1;
        }

        if(pKey == NULL)
        {
            printf("Error3 in counter\n\r");
            return 2;
        }

        int i;
        int n[26] = {0};
        int Maxsymbol = 0;
        int c;

        while((c = fgetc(File)) != EOF)
        {
            if((c >= 'A')&&(c <= 'Z'))
                n[c - 'A']++;
            if((c >= 'a')&&(c <= 'z'))
                n[c - 'a']++;
        }

        if(feof(File) == 0)
        {
            printf("Error in feof\n\r");
            return 3;
        }

        for (i = 0;i < 26;i++)
            if (n[i] >= n[Maxsymbol])
                Maxsymbol = i;

        Maxsymbol -= 'e'-'a';

        if (Maxsymbol < 0)
        Maxsymbol += 26;

        *pKey = Maxsymbol;

        return 0;
    }

    int decypher(int Key, FILE *f)
    {
        if(f == NULL)
        {
            printf("Error of decypher\n\r");
            return 1;
        }

        int c;
        FILE *Copy = NULL;
        char Filename_2[MAX_PATH];

        while (Copy == NULL)
        {
            if ((printf("Input correct path to the file 2: \n\r")) < 0)
            {
                printf("error of decypher");
                return 2;
            }
            if ((fgets(Filename_2, MAX_PATH, stdin)) == NULL)
            {
                printf("error");
                return 3;
            }
            Filename_2[strlen(Filename_2)-1] = '\0';

            if ((Copy = fopen(Filename_2, "w+")) == NULL)
                printf("Error: incorrect path1. \n\r");
        }
        while((c = fgetc(f)) != EOF)
        {
            if(((c >= 'A') && (c <= 'Z') && (c - Key < 'A')) || ((c >= 'a') && (c <= 'z') && (c - Key < 'a')))
            {
                c -= Key - 26;
            }
            else if(((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')))
            {
                c -= Key;
            }

            if (fprintf(Copy, "%c", c) < 0)
                return 4;
        }

        if (fclose(Copy) != 0)
            {
                printf("Error in fclose2");
                return 5;
            }

        return 0;
    }
