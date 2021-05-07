#define _GNU_SOURCE
#include <openssl/md5.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
// Commented <unistd.h> out because it's not actually used
//#include <unistd.h>

#define MAX_USERNAME_LENGTH 64
#define PASSWORD_LENGTH 6

// 26^6 = 308915776 represents the number of possible passwords following the given constraints
#define NUMBER_POSSIBLE_PASSWORDS 308915776

// Size of our hashtable that holds username/password hash pairs
// After testing many values (401, 1009, 9973, 100003, 65536, 32768, 8192), we found 4096 to
// give the best speeds
#define HASHTABLE_SIZE 4096

/**
 * Find a six character lower-case alphabetic password that hashes
 * to the given hash value.
 *
 * \param input_hash  An array of MD5_DIGEST_LENGTH bytes that holds the hash of a password
 * \param output      A pointer to memory with space for a six character password + '\0'
 * \returns           0 if the password was cracked. -1 otherwise.
 */
int crack_single_password(uint8_t* input_hash, char* output){
  // To start our password search at "aaaaaa", begin candidate as "(a-1)aaaaa" so that the
  // first iteration of the loop below increments it to "aaaaaa"
  char candidate_passwd[PASSWORD_LENGTH+1] = {'a'-1, 'a', 'a', 'a', 'a', 'a', '\0'};

  // Loop through all 'NUMBER_POSSIBLE_PASSWORDS' possible candidate passwords
  for (int i = 0; i < NUMBER_POSSIBLE_PASSWORDS; i++){
    // Advance the character in the first position of 'candidate_passwd'
    candidate_passwd[0]++;

    // "Carry over" as necessary for all positions of 'candidate_passwd' (final position will
    //  never be carried over because of the limit imposed by 'NUMBER_POSSIBLE_PASSWORDS')
    for (int j = 0; j < PASSWORD_LENGTH; j++){

      // If we advance a character past 'z'
      if (candidate_passwd[j] > 'z'){
        // Reset the character to 'a'
        candidate_passwd[j] = 'a';
        // And "carry over" to the next position
        candidate_passwd[j+1]++;
      }
      // If a given position doesn't need to be "carried over", subsequent positions won't need
      // to be "carried over" either on this iteration, so we can break
      else{
        break;
      }
    }

    // Take our candidate password and hash it using MD5
    uint8_t candidate_hash[MD5_DIGEST_LENGTH];  // Holds the hash of the candidate password
    // Do the hash
    MD5((unsigned char*)candidate_passwd, strlen(candidate_passwd), candidate_hash);

    // Now check if the hash of the candidate password matches the input hash
    if (memcmp(input_hash, candidate_hash, MD5_DIGEST_LENGTH) == 0){
      // Match! Copy the password to the output and return 0 (success)
      strncpy(output, candidate_passwd, PASSWORD_LENGTH + 1);
      return 0;
    }
  }

  // Return -1 (failure) if the password could not be cracked
  return -1;
}

// Struct for holding each username/password hash pair
typedef struct password_set_node{
  char username[MAX_USERNAME_LENGTH];
  uint8_t password_hash[MD5_DIGEST_LENGTH];
} password_set_node_t;

// Source: (referenced for help in implementing a hash table)
//  Data Structures & Problem Solving Using Java, Mark Allen Weiss (207 Textbook)

/**
 * This struct is the root of the hash table that will hold username and password hash pairs
 * in the form of password_set_nodes.
 */
typedef struct password_set{
  password_set_node_t* hashtable[HASHTABLE_SIZE]; // The actual hashtable
  int uncracked; // Number of uncracked entries remaining
} password_set_t;

/**
 * Initialize a password set.
 *
 * \param passwords  A pointer to allocated memory that will hold a password set
 */
void init_password_set(password_set_t* passwords){
  // Set each cell of the hashtable to NULL
  for (int i=0; i < HASHTABLE_SIZE; i++){
    passwords->hashtable[i] = NULL;
  }
  // Set number of uncracked entries to 0 because no entries exist yet
  passwords->uncracked = 0;
}

// Source: djb2 hash function for strings by Dan Bernstein
/**
 * Hashes a string key (the MD5 password hash casted as a string, in our case) to give a
 * number that will be moduloed by the hashtable size to give a hashtable position
 * corresponding to the key
 *
 * \param str  A pointer to the string being hashed
 */
unsigned long hash(unsigned char* str){
  unsigned long hash = 5381; // "Magic" prime number from Dan Bernstein that gives good results
  int c;
  // Only use part of the input when generating the hash for speed improvements
  str = &str[13];

  // Now that str has been advanced, use the last part of it to calculate the hash
  for (int i=0; i<MD5_DIGEST_LENGTH-13; i++){
    c = *str++;
    hash = ((hash << 5) + hash) + c;
  }

  return hash;
}

/**
 * Add a password to a password set
 *
 * \param passwords   A pointer to a password set initialized with the function above.
 * \param username    The name of the user being added. The memory that holds this string's
 *                    characters will be reused, so if you keep a copy you must duplicate the
 *                    string.
 * \param password_hash   An array of MD5_DIGEST_LENGTH bytes that holds the hash of this user's
 *                        password. The memory that holds this array will be reused, so you must
 *                        make a copy of this value if you retain it in your data structure.
 */
void add_password(password_set_t* passwords, char* username, uint8_t* password_hash){
  // Allocate space for a new password_set_node to hold the username/password hash pair
  password_set_node_t* new = malloc(sizeof(password_set_node_t));

  // Copy the username and password hash into the fields of new
  strncpy(new->username, username, MAX_USERNAME_LENGTH);
  memmove(new->password_hash, password_hash, MD5_DIGEST_LENGTH);

  // Use the hash function on 'password_hash' and modulo it to generate a hashtable position
  // within the bounds of 'HASHTABLE_SIZE'
  int position = hash((unsigned char*)password_hash)%HASHTABLE_SIZE;

  int i = 1; // Start index for quadratic probing at 1

  // Start at 'position' and probe until we find an open cell
  while((passwords->hashtable[position] != NULL)){
    // Quadratic probing: if the current cell is filled, move to the next probe position
    // while being careful to stay within the bounds of 'HASHTABLE_SIZE'
    position = (position + (i * i)) % HASHTABLE_SIZE;
    // Increment the quadratic probing index
    i++;
  }

  // An empty position was found, insert the entry
  passwords->hashtable[position] = new;
  // Indicate that we have added an entry to be cracked
  passwords->uncracked++;
}

// Struct for passing in thread arguments
typedef struct arg {
  password_set_t* passwords;
  // Each thread will begin its candidate password search from a unique starting point
  // within the possible password space
  char* starting;
} arg_t;

// Struct for thread return value
typedef struct ret {
  int passwords_cracked;
} ret_t;

/**
 * Runs in a thread to crack all the passwords available that fall within its assigned password
 * space to search through.
 *
 * \param args   A void pointer to the struct of arguments for the given thread. This struct
 *               contains a pointer to the password set and a candidate password string to
 *               start searching from.
 */
void* password_cracker(void* args){

  // Allocate space for a struct to hold the thread's return value
  ret_t* return_value = malloc(sizeof(ret_t));

  // Cast args to an arg_t* and store as 'thread_args'
  arg_t* thread_args = (arg_t*)args;
  // Use 'thread_args' to access the password set and the thread's assigned starting point
  password_set_t* passwords = thread_args->passwords;
  char* starting = thread_args->starting;

  // Copy the starting point string into 'candidate_passwd'; the next generated string
  // will be the first candidate that this thread checks
  char candidate_passwd[PASSWORD_LENGTH+1];
  strncpy(candidate_passwd, starting, PASSWORD_LENGTH+1);

  int cracked_so_far = 0; // Keeps track of how many passwords have been cracked

  // Loop through 'NUMBER_POSSIBLE_PASSWORDS'/4 possible candidate passwords
  for (int i = 0; i < NUMBER_POSSIBLE_PASSWORDS/4; i++){

    // If all passwords have been cracked, store 'cracked_so_far' in the
    // 'passwords_cracked' field of the 'return_value' struct and return
    if (passwords->uncracked == 0){
      return_value->passwords_cracked = cracked_so_far;
      return (void*)return_value;
    }

    // Advance the character in the first position of 'candidate_passwd'
    candidate_passwd[0]++;

    // "Carry over" as necessary for all positions of 'candidate_passwd' (final position will
    // never be carried over because of the limit imposed by 'NUMBER_POSSIBLE_PASSWORDS'
    for (int j = 0; j < PASSWORD_LENGTH; j++){

      // If we advance a character past 'z'
      if (candidate_passwd[j] > 'z'){
        // Reset the character to 'a'
        candidate_passwd[j] = 'a';
        // And carry over to the next position
        candidate_passwd[j+1]++;
      }
      // If a given position doesn't need to be carried over, subsequent positions won't need
      // to be carried over either on this iteration, so we can break
      else{
        break;
      }
    }

    // Take our candidate password and hash it using MD5
    uint8_t candidate_hash[MD5_DIGEST_LENGTH];  // Holds the hash of the candidate password
    // Do the hash (replaced 'strlen(candidate_passwd)') with 'PASSWORD_LENGTH' to improve speed
    MD5((unsigned char*)candidate_passwd, PASSWORD_LENGTH, candidate_hash);  //< Do the hash


    // Use the hash function on 'candidate_hash' and modulo it to generate a hashtable position
    // within the bounds of 'HASHTABLE_SIZE' where 'candidate_hash' could be found
    int search_position = hash((unsigned char*)candidate_hash)%HASHTABLE_SIZE;

    // Start index for quadratic probing at 1
    int i = 1;

    // Start at 'search_position' and probe until we find an empty cell
    while (passwords->hashtable[search_position] != NULL){
      // The current cell is not empty, so we store a pointer to it
      password_set_node_t* current = passwords->hashtable[search_position];

      // If the candidate hash matches the hash entry in the current cell
      if (memcmp(current->password_hash, candidate_hash, MD5_DIGEST_LENGTH) == 0){
        // Print the username and the cracked password
        printf("%s %s\n", current->username, candidate_passwd);
        // Increment 'cracked_so_far' and decrement 'uncracked'
        cracked_so_far++;
        passwords->uncracked--;
      }

      // Whether a match was found or not, use quadratic probing to move to the next probe
      // position (this lets us check for password repeats)
      search_position = (search_position + (i * i)) % HASHTABLE_SIZE;
      // Increment the quadratic probing index
      i++;
    }
  }

  // Once all candidates have been exhausted, store 'cracked_so_far' in the
  // 'passwords_cracked' field of the 'return_value' struct and return
  return_value->passwords_cracked = cracked_so_far;
  return (void*)return_value;
}

/**
 * Creates 4 threads and has each of them run 'password_cracker()' on the complete set of
 * username/password hash pairs to crack, but from unique starting points within the
 * possible password space.
 *
 * \param passwords   A pointer to a password set initialized with the function above.
 */
int crack_password_list(password_set_t* passwords){
  pthread_t threads[4]; // Array for keeping track of the 4 threads we will create

  // An arg_t array used to provide arguments to each of the 4 threads
  // Each thread will generate 'NUMBER_POSSIBLE_PASSWORDS'/4 candidates; thus, separate each
  // starting point by that amount of loop advances as looped in 'password_cracker()' and
  // note that 'a'-1 = '`'
  arg_t args[4] = {{passwords, "`aaaaa"}, {passwords, "zzzzmg"}, {passwords, "zzzzzm"}, {passwords, "zzzzmt"}};

  // Create 4 threads to run 'password_cracker()' on each section of the possible candidate
  // passwords
  for(int i = 0; i < 4; i++){

    // If 'pthread_create' fails, notify and exit with EXIT_FAILURE
    if(pthread_create(&threads[i], NULL, password_cracker, &args[i])){
      perror("pthread_create failed");
      exit(EXIT_FAILURE);
    }
  }

  // A ret_t array used to store the return values of each thread
  ret_t* results[4];
  int total = 0; // The total number of passwords cracked by all 4 threads

  // Wait for all 4 threads to finish
  for(int i = 0; i < 4; i++){

    // If 'pthread_join' fails, notify and exit with EXIT_FAILURE
    if(pthread_join(threads[i], (void**) &results[i])){
      perror("pthread_join failed");
      exit(EXIT_FAILURE);
    }

    // When a thread finishes, add its return value (the number of passwords it cracked) to
    // the total number of passwords cracked by all 4 threads
    total += results[i]->passwords_cracked;
  }

  // Return the total number of passwords cracked by all 4 threads
  return total;
}

/******************** Provided Code ***********************/

/**
 * Convert a string representation of an MD5 hash to a sequence
 * of bytes. The input md5_string must be 32 characters long, and
 * the output buffer bytes must have room for MD5_DIGEST_LENGTH
 * bytes.
 *
 * \param md5_string  The md5 string representation
 * \param bytes       The destination buffer for the converted md5 hash
 * \returns           0 on success, -1 otherwise
 */
int md5_string_to_bytes(const char* md5_string, uint8_t* bytes) {
  // Check for a valid MD5 string (we commented this check out for speed improvements)
  //if (strlen(md5_string) != 2 * MD5_DIGEST_LENGTH) return -1;

  // Start our "cursor" at the start of the string
  const char* pos = md5_string;

  // Loop until we've read enough bytes
  for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++) {
    // Read one byte (two characters)
    int rc = sscanf(pos, "%2hhx", &bytes[i]);
    if (rc != 1) return -1;

    // Move the "cursor" to the next hexadecimal byte
    pos += 2;
  }

  return 0;
}

void print_usage(const char* exec_name) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s single <MD5 hash>\n", exec_name);
  fprintf(stderr, "  %s list <password file name>\n", exec_name);
}

int main(int argc, char** argv) {

  if (argc != 3) {
    print_usage(argv[0]);
    exit(1);
  }

  if (strcmp(argv[1], "single") == 0) {
    // The input MD5 hash is a string in hexadecimal. Convert it to bytes.
    uint8_t input_hash[MD5_DIGEST_LENGTH];
    if (md5_string_to_bytes(argv[2], input_hash)) {
      fprintf(stderr, "Input has value %s is not a valid MD5 hash.\n", argv[2]);
      exit(1);
    }

    // Now call the crack_single_password function
    char result[7];
    if (crack_single_password(input_hash, result)) {
      printf("No matching password found.\n");
    } else {
      printf("%s\n", result);
    }

  } else if (strcmp(argv[1], "list") == 0) {
    // Make and initialize a password set
    password_set_t passwords;
    init_password_set(&passwords);

    // Open the password file
    FILE* password_file = fopen(argv[2], "r");
    if (password_file == NULL) {
      perror("opening password file");
      exit(2);
    }

    int password_count = 0;

    // Read until we hit the end of the file
    while (!feof(password_file)) {
      // Make space to hold the username
      char username[MAX_USERNAME_LENGTH];

      // Make space to hold the MD5 string
      char md5_string[MD5_DIGEST_LENGTH * 2 + 1];

      // Make space to hold the MD5 bytes
      uint8_t password_hash[MD5_DIGEST_LENGTH];

      // Try to read. The space in the format string is required to eat the newline
      if (fscanf(password_file, "%s %s ", username, md5_string) != 2) {
        fprintf(stderr, "Error reading password file: malformed line\n");
        exit(2);
      }

      // Convert the MD5 string to MD5 bytes in our new node
      if (md5_string_to_bytes(md5_string, password_hash) != 0) {
        fprintf(stderr, "Error reading MD5\n");
        exit(2);
      }

      // Add the password to the password set
      add_password(&passwords, username, password_hash);
      password_count++;
    }

    // Now run the password list cracker
    int cracked = crack_password_list(&passwords);

    printf("Cracked %d of %d passwords.\n", cracked, password_count);

  } else {
    print_usage(argv[0]);
    exit(1);
  }

  return 0;
}