#include "afinet.h"
#ifndef g_assert_cmpstr
#include "gtestutils/gtestutils.h"
#endif

/* fixtures for setting up AFSocketOptions */

static void
setup_socket_options(AFSocketOptions *so, gconstpointer user_data)
{
  afsocket_options_init(so);
}

static void
teardown_socket_options(AFSocketOptions *so, gconstpointer user_data)
{
  afsocket_options_free(so);
}

static void
test_afsocket_options_set_transport_stores_value(AFSocketOptions *so, gconstpointer user_data)
{
  afsocket_options_set_transport(so, "foobar");
  g_assert_cmpstr(so->transport, ==, "foobar");
}

static void
test_afsocket_options_apply_transport_returns_success(AFSocketOptions *so, gconstpointer user_data)
{
  g_assert_cmpint(afsocket_apply_transport(so), !=, FALSE);
}

#define add_afsocket_options_test(testcase) \
  G_STMT_START {                                                        \
    g_test_add("/afsocket_options/" ## testcase, AFSocketOptions, NULL, setup_socket_options, testcase, teardown_socket_options); \
  } G_STMT_END

int
main(int argc, char *argv[])
{
  g_test_init(&argc, &argv, NULL);

  add_afsocket_options_test(test_afsocket_options_set_transport);
  add_afsocket_options_test(test_afsocket_options_set_transport_stores_value);
  return g_test_run();
}
