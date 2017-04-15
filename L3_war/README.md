# Level 3 - Master - WAR

```
WAR
Win a simple Card Game. Source. Connect on shell2017.picoctf.com:4415.

 HINTS
Bugs typically happen in groups. If you find one, what does it allow you to do?
```

Note. I solved this by just throwing data at it.
1) maxed out the name with 'A'*32
2) kept betting 1 coin till I started winning and then bet max till I got a prompt.

This doesn't help you understand the vulnerability though, and why it does this. 
So lets take a look at the following structure for saving the game state
```C
typedef struct _gameState{
  int playerMoney;
  player ctfer;
  char name[NAMEBUFFLEN];
  size_t deckSize;
  player opponent;
} gameState;
```
Now look at how the name is being read in and specifically the null termination:
```C
//Reads input from user, and properly terminates the string
unsigned int readInput(char * buff, unsigned int len){
    size_t count = 0;
    char c;
    while((c = getchar()) != '\n' && c != EOF){
        if(count < (len-1)){
            buff[count] = c;
            count++;
        }
    }
    buff[count+1] = '\x00';
    return count;
}
```

This part here `buff[count+1] = '\x00';` will end up setting the deck size to zero if you give it enough characters in your name.
Why is this useful? Lets look at this code here:
```C
        //TODO: Implement card switching hands. Cheap hack here for playability
        gameData.deckSize--;
        if(gameData.deckSize == 0){
            printf("All card used. Card switching will be implemented in v1.0, someday.\n");
            exit(0);
        }
```
The code will decrement the counter before checking the deckSize. It will also only check for zero, which means that `-1` is perfectly fine and won't trigger the exit condition.

Now... Why is that important?
Well, the player structure is what holds your cards:
```
typedef struct _player{
    int money;
    deck playerCards;                    //<---- Cards
} player;

typedef struct _gameState{
  int playerMoney;
  player ctfer;                         //<----- Cards are right before name.
  char name[NAMEBUFFLEN];
  size_t deckSize;
  player opponent;
} gameState;
```
So now we have the ability to play past the 'rigged' deck that the application set up for us.

If we just put 32 'A' characters in the name we get this error message:
```
You have a 65 of suit 65.
You won? Hmmm something must be wrong...
Cheater. That's not actually a valid card.
```
Remember 'A' = 0x41 = 65. So it's reading our name as a set of cards. Great, lets just put the values we want in there, and we can win.
I put in '\x04'*32, for the name, so that I'd have 16 hands of `4 of suite 4` and always win the bet.

But you can also decide to play through this and eventually you'll get to memory that is suited for winning because you step right into your opponents deck.

So in summary
- you don't have to write an exploit for this level
- you didn't necessarily need to 'see' the bug in the code in order to get the first hints
- you just have to throw a bunch of data at the problem and see what breaks

Full exploit code in the [exploit.py](exploit.py) file.

