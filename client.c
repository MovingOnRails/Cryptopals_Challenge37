#include <stdio.h>

#include <curl/curl.h>
#include <gmp.h>
#include <cjson/cJSON.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>


#include "../../set1/Challenge2/xorHelper.c"

unsigned char salt_hex[33];
unsigned char password[17] = "YELLOW SUBMARINE";
int password_length = 16;
unsigned char* B_hex;
int B_hex_length = 0;
unsigned char* A_hex;
int A_hex_length = 0;

// Struct to store libcurl response
struct MemoryBlock {
    char *memory;
    size_t size;
};

// Callback to handle incoming data
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryBlock *mem = (struct MemoryBlock *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) return 0; // out of memory!

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

static size_t silence_callback(void *contents, size_t size, size_t nmemb, void* userp){
    return size*nmemb;
}

void extract_salt(char *json_string) {
    cJSON *root = cJSON_Parse(json_string);
    if (!root) {
        printf("Error parsing JSON\n");
        return;
    }

    // Extracting the "salt"
    cJSON *salt_item = cJSON_GetObjectItemCaseSensitive(root, "salt");
    if (cJSON_IsString(salt_item) && (salt_item->valuestring != NULL)) {
        printf("salt_hex: %s\n", salt_item->valuestring);
        memcpy(salt_hex, salt_item->valuestring, 32);
    }
    cJSON_Delete(root);
}

void extract_B(char *json_string) {
    cJSON *root = cJSON_Parse(json_string);
    if (!root) {
        printf("Error parsing JSON\n");
        return;
    }

    // Extracting B
    cJSON *B_item = cJSON_GetObjectItemCaseSensitive(root, "B");
    if (cJSON_IsString(B_item) && (B_item->valuestring != NULL)) {
        printf("B_hex: %s\n", B_item->valuestring);
        int B_hex_length_local = strlen(B_item->valuestring);
        B_hex = malloc(B_hex_length_local+1);
        if(B_hex == NULL){
            printf("Error after malloc\n");
            exit(EXIT_FAILURE);
        }
        memcpy(B_hex, B_item->valuestring, B_hex_length_local);
        B_hex[B_hex_length_local] = '\0';
        B_hex_length = B_hex_length_local;
    }
    cJSON_Delete(root);
}

unsigned char* get_xH_hex(){
    unsigned char* salt_bytes = malloc(32);
    int salt_bytes_length = 0;
    salt_bytes = hexStringToRawString(salt_hex, salt_bytes, &salt_bytes_length);

    unsigned char* salt_and_password_to_hash = malloc(salt_bytes_length+password_length);
    memcpy(salt_and_password_to_hash, salt_bytes, salt_bytes_length);
    memcpy(salt_and_password_to_hash+salt_bytes_length,password,password_length);
    unsigned char xH_bytes[32];
    SHA256(salt_and_password_to_hash,salt_bytes_length+password_length,xH_bytes);
    unsigned char* xH_hex = malloc(65);
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        sprintf(xH_hex + (i * 2), "%02x", xH_bytes[i]);
    }
    return xH_hex;
}

void compute_u(mpz_t u, mpz_t A, mpz_t B, mpz_t N) {
    // Determine the size of N in bytes (this is the standard padding size)
    size_t n_bytes = (mpz_sizeinbase(N, 2) + 7) / 8;

    unsigned char *buffer_A = malloc(n_bytes);
    unsigned char *buffer_B = malloc(n_bytes);
    
    size_t count_A, count_B;

    // mpz_export(buffer, &written, order, size, endian, nails, op)
    // order=1 (Big Endian), size=1 (byte-wise), endian=1 (Big Endian)
    mpz_export(buffer_A, &count_A, 1, 1, 1, 0, A);

    // Note: we offset the pointer by n_bytes to leave space for A
    mpz_export(buffer_B, &count_B, 1, 1, 1, 0, B);

    unsigned char* combined = malloc(count_A+count_B);
    memcpy(combined, buffer_A, count_A);
    memcpy(combined+count_A, buffer_B, count_B);
    // Generate SHA256 hash
    unsigned char uH_bytes[SHA256_DIGEST_LENGTH];
    SHA256(combined, count_A+count_B, uH_bytes);

    // Load the hash bytes back into the GMP variable 'u'
    mpz_import(u, SHA256_DIGEST_LENGTH, 1, 1, 1, 0, uH_bytes);

    free(combined);
}

int main(){
    

    // --------------------STARTUP--------------------
    mpz_t g, k, N, a, v;
    mpz_inits(g, k, N, a, v, NULL);
    gmp_randstate_t state;

    mpz_set_ui(g, 2);
    mpz_set_ui(k, 3);
    const char* nist_p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";

    mpz_set_str(N, nist_p, 16);
    gmp_printf("N: %Zd\n", N);
    gmp_printf("g: %Zd\n", g);
    gmp_printf("k: %Zd\n", k);

    gmp_randinit_default(state);
    gmp_randseed_ui(state, 12345);

    mpz_set_ui(a, 0);
    while(mpz_cmp_ui(a, 0) == 0){
        mpz_urandomm(a,state,N);
    }


    // ------------------Client get_salt()------------------
    // send I
    // Server returns SALT
    CURL* curl_handle;
    CURLcode res;
    struct MemoryBlock getsalt_chunk = {malloc(32), 0};

    curl_handle = curl_easy_init();

    if(curl_handle){
        curl_easy_setopt(curl_handle, CURLOPT_URL, "localhost:5000/get_salt");
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&getsalt_chunk);
    } else {
        printf("curl_handle failed\n");
        return 1;
    }
    res = curl_easy_perform(curl_handle);
    long response_code = 0;
    if(res == CURLE_OK){
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code);
        if(response_code == 201){
            printf("get_salt() successful\n");
            extract_salt(getsalt_chunk.memory);
        }
    } else {
        printf("curl request failed\n");
        return 1;
    }
    free(getsalt_chunk.memory);
    
    

    // ------------------Client register()------------------
    // send I, v
    // Server returns OK
    

    unsigned char* xH_hex = get_xH_hex();
    mpz_t x;
    mpz_inits(x, NULL);
    mpz_set_str(x, xH_hex, 16);
    free(xH_hex);

    mpz_powm(v, g, x, N);
    char* v_hex = mpz_get_str(NULL, 16, v);
    printf("v_hex: %s\n", v_hex);
    
    curl_easy_reset(curl_handle);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "v", v_hex);
    char* json_body = cJSON_PrintUnformatted(root);
    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json_body);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl_handle, CURLOPT_URL, "localhost:5000/register");
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, silence_callback);

    res = curl_easy_perform(curl_handle);
    if(res == CURLE_OK){
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE,&response_code);
        if(response_code == 200){
            printf("register() successful\n");
        } else {
            printf("register() unsuccessful\n");
            return 1;
        }
    } else {
        printf("register() curl request failed\n");
        return 1;
    }
    curl_slist_free_all(headers);
    free(json_body);
    cJSON_Delete(root);

    void (*freefunc)(void *, size_t);
    mp_get_memory_functions(NULL, NULL, &freefunc);
    freefunc(v_hex, strlen(v_hex) + 1);
    // I could add garbate to xH and set x to a different number if I want 
    // to make the values dissapear for safety reasons




    // ------------------Client auth_first_step()------------------
    // send I, A = 0
    // Server returns B

    curl_easy_reset(curl_handle);

    // A = 0
    mpz_t A;
    mpz_inits(A, NULL);

    char A_hex_local[3] = "00";
    printf("A_hex: %s\n", A_hex_local);
    A_hex = malloc(strlen(A_hex_local)+1);
    A_hex_length = strlen(A_hex_local);
    memcpy(A_hex, A_hex_local, strlen(A_hex_local));
    A_hex[A_hex_length] = '\0';

    cJSON *root2 = cJSON_CreateObject();
    cJSON_AddStringToObject(root2,"I","alice@alicemail.com");
    cJSON_AddStringToObject(root2,"A",A_hex_local);
    char* json_body2 = cJSON_PrintUnformatted(root2);

    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json_body2);

    struct curl_slist *headers2 = NULL;
    headers2 = curl_slist_append(headers2, "Content-Type: application/json");
    headers2 = curl_slist_append(headers2, "Accept: application/json");
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers2);

    curl_easy_setopt(curl_handle, CURLOPT_URL, "localhost:5000/auth_first_step");
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteCallback);

    struct MemoryBlock authfirststep_chunk = {malloc(1), 0};
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&authfirststep_chunk);

    curl_easy_perform(curl_handle);
    if(res == CURLE_OK){
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE,&response_code);
        if(response_code == 200){
            extract_B(authfirststep_chunk.memory);
            printf("B_hex: %s\n",B_hex);
            printf("auth_first_step() successful\n");
        } else {
            printf("auth_first_step() unsuccessful\n");
            return 1;
        }
    } else {
        printf("auth_first_step() curl request failed\n");
        return 1;
    }
    curl_slist_free_all(headers2);
    free(json_body2);
    cJSON_Delete(root2);

    // ----------------Compute x, xH, u, uH, S and K----------------

    // I should compute again x and xH BUT I'm not doing it, I'll use the already computed
    // uH = SHA256(A|B)
    mpz_t u, B;
    mpz_inits(u, B, NULL);

    mpz_set_str(B, B_hex, 16);
    compute_u(u, A, B, N);

    // ----------------Compute HMAC_SHA256(K, salt)----------------
    // S =  0
    mpz_t S;
    mpz_inits(S, NULL);

    mpz_set_ui(S, 0);

    size_t n_bytes = (mpz_sizeinbase(N, 2) + 7) / 8; 

    size_t count_S;
    unsigned char *buffer_S = calloc(1, n_bytes);
    size_t actual_bytes = (mpz_sizeinbase(S, 2) + 7) / 8;
    mpz_export(buffer_S + (n_bytes - actual_bytes), &count_S, 1, 1, 1, 0, S);
    unsigned char K[SHA256_DIGEST_LENGTH];
    SHA256(buffer_S,n_bytes,K);
    printf("S (padded): ");
    for(int i=0;i<count_S;i++){
        printf("%02x", buffer_S[i]);
    }
    printf("\n");
    free(buffer_S);
    // 2. Generate actual HMAC
    unsigned char hmac_result[SHA256_DIGEST_LENGTH];
    unsigned int hmac_len;
    unsigned char* salt_bytes = malloc(16);
    int salt_bytes_length = 0;
    salt_bytes = hexStringToRawString(salt_hex,salt_bytes,&salt_bytes_length);
    HMAC(EVP_sha256(), K, SHA256_DIGEST_LENGTH, salt_bytes, 16, hmac_result, &hmac_len);
    // 3. Convert hmac_result to Hex for the JSON body
    char hmac_hex[65];
    for(int i = 0; i < 32; i++) {
        sprintf(hmac_hex + (i * 2), "%02x", hmac_result[i]);
    }
    printf("\n");
    printf("hmac_result: %s\n", hmac_hex);

    // Generate HMAC

    // ----------------Send HMAC to Server----------------
    // Server returns 200 if okay else 401

    curl_easy_reset(curl_handle);

    cJSON *root3 = cJSON_CreateObject();
    cJSON_AddStringToObject(root3,"HMAC",hmac_hex);
    char* json_body3 = cJSON_PrintUnformatted(root3);
    
    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json_body3);

    struct curl_slist *headers3 = NULL;
    headers3 = curl_slist_append(headers3, "Content-Type: application/json");
    headers3 = curl_slist_append(headers3, "Accept: application/json");
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers3);

    curl_easy_setopt(curl_handle, CURLOPT_URL, "localhost:5000/auth_last_step");
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, silence_callback);

    curl_easy_perform(curl_handle);
    if(res == CURLE_OK){
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE,&response_code);
        if(response_code == 200){
            printf("auth_last_step() successful\n");
        } else {
            printf("auth_last_step() unsuccessful\n");
            return 1;
        }
    } else {
        printf("auth_last_step() curl request failed\n");
        return 1;
    }
    curl_slist_free_all(headers3);
    free(json_body3);
    cJSON_Delete(root3);

    free(A_hex);
    free(B_hex);
    return 0;
}