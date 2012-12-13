#include "afinet.h"
#ifndef g_assert_cmpstr
#include "gtestutils/gtestutils.h"
#endif

static void
test_afinet_apply_transport(void)
{
  g_assert_not_reached();
}

int
main(int argc, char *argv[])
{
  g_test_init(&argc, &argv);

  g_test_add_func("/afinet/apply_transport", test_afinet_apply_transport);
  return g_test_run();
}
