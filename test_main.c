// test_main.c
#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

extern int set_socket_timeout(int sockfd, int timeout);
extern SSL_CTX* init_ssl(void);

START_TEST(test_set_socket_timeout) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ne(sockfd, -1);
    int result = set_socket_timeout(sockfd, 10);
    ck_assert_int_eq(result, 0);
    close(sockfd);
}
END_TEST

START_TEST(test_init_ssl) {
    SSL_CTX *ctx = init_ssl();
    ck_assert_ptr_nonnull(ctx);
    SSL_CTX_free(ctx);
}
END_TEST

Suite *main_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Main");

    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_set_socket_timeout);
    tcase_add_test(tc_core, test_init_ssl);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = main_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
