/*
 * fpc1540ta - FPC1540 match-on-chip via the stock trustlet in userspace
 *
 * The helper socket is serviced on GTask worker threads so the libfprint main
 * context never blocks.  One GID ("fingerprint set") per finger, each with its
 * own wrapped DB file <dir>/set-<gid>.bin.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "fpc1540ta"

#include "drivers_api.h"
#include <glib/gstdio.h>

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define FPC1540TA_SOCK_ENV     "FPC1540TA_SOCK"
#define FPC1540TA_DIR_ENV      "FPC1540TA_DIR"
#define FPC1540TA_DEFAULT_SOCK "/run/fpc1540ta.sock"
#define FPC1540TA_DEFAULT_DIR  "/var/lib/fpc1540ta"
#define FPC1540TA_NR_STAGES    20

struct _FpiDeviceFpc1540Ta
{
  FpDevice  parent;
  int       fd;
  GMutex    lock;
  FpPrint  *enroll_print;
  FpPrint  *op_target;
  GPtrArray *op_prints;
  guint32   out_gid;
  guint32   out_score;
  gboolean  out_matched;
};

G_DECLARE_FINAL_TYPE (FpiDeviceFpc1540Ta, fpi_device_fpc1540ta, FPI,
                      DEVICE_FPC1540TA, FpDevice);
G_DEFINE_TYPE (FpiDeviceFpc1540Ta, fpi_device_fpc1540ta, FP_TYPE_DEVICE);

static FpiDeviceFpc1540Ta *g_self;

/* ------------------------------------------------------------------ */
/* Socket helpers                                                      */
/* ------------------------------------------------------------------ */

static const char *ta_sock_path (void)
{
  const char *s = g_getenv (FPC1540TA_SOCK_ENV);
  return s ? s : FPC1540TA_DEFAULT_SOCK;
}
static const char *ta_dir (void)
{
  const char *s = g_getenv (FPC1540TA_DIR_ENV);
  return s ? s : FPC1540TA_DEFAULT_DIR;
}
static gchar *ta_set_path (guint32 gid)
{
  return g_strdup_printf ("%s/set-%u.bin", ta_dir (), gid);
}

static int
ta_connect (GError **error)
{
  int fd = socket (AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un sa;
  if (fd < 0)
    { g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
                   "socket: %s", g_strerror (errno)); return -1; }
  memset (&sa, 0, sizeof sa);
  sa.sun_family = AF_UNIX;
  g_strlcpy (sa.sun_path, ta_sock_path (), sizeof sa.sun_path);
  if (connect (fd, (struct sockaddr *) &sa, sizeof sa) < 0)
    { g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
                   "connect %s: %s", ta_sock_path (), g_strerror (errno));
      close (fd); return -1; }
  return fd;
}

static gboolean
ta_read_line (int fd, char *buf, size_t n, int timeout_ms)
{
  size_t o = 0;
  while (o + 1 < n)
    {
      struct pollfd p = { .fd = fd, .events = POLLIN };
      ssize_t r;
      if (poll (&p, 1, timeout_ms) <= 0)
        return FALSE;
      r = read (fd, buf + o, 1);
      if (r <= 0)
        return FALSE;
      if (buf[o] == '\n')
        { buf[o] = '\0'; return TRUE; }
      o++;
    }
  buf[n - 1] = '\0';
  return TRUE;
}

static gboolean
ta_write (FpiDeviceFpc1540Ta *self, const char *cmd)
{
  g_autofree char *line = g_strdup_printf ("%s\n", cmd);
  return write (self->fd, line, strlen (line)) == (ssize_t) strlen (line);
}

static gboolean
ta_cmd (FpiDeviceFpc1540Ta *self, const char *cmd, char *reply, size_t rn,
        int timeout_ms)
{
  return ta_write (self, cmd) && ta_read_line (self->fd, reply, rn, timeout_ms);
}

static GArray *
ta_scan_gids (void)
{
  g_autoptr(GArray) gids = g_array_new (FALSE, FALSE, sizeof (guint32));
  g_autoptr(GDir) dir = g_dir_open (ta_dir (), 0, NULL);
  const char *name;

  while (dir && (name = g_dir_read_name (dir)))
    {
      guint32 gid;
      if (sscanf (name, "set-%u.bin", &gid) == 1)
        g_array_append_val (gids, gid);
    }
  for (guint i = 1; i < gids->len; i++)
    {
      guint32 v = g_array_index (gids, guint32, i);
      gint j = (gint) i - 1;
      while (j >= 0 && g_array_index (gids, guint32, j) > v)
        { g_array_index (gids, guint32, j + 1) = g_array_index (gids, guint32, j); j--; }
      g_array_index (gids, guint32, j + 1) = v;
    }
  return g_steal_pointer (&gids);
}

static guint32
ta_next_gid (void)
{
  g_autoptr(GArray) gids = ta_scan_gids ();
  guint32 next = 1;
  for (guint i = 0; i < gids->len; i++)
    if (g_array_index (gids, guint32, i) >= next)
      next = g_array_index (gids, guint32, i) + 1;
  return next;
}

/* ------------------------------------------------------------------ */
/* open / close                                                        */
/* ------------------------------------------------------------------ */

static void
open_thread (GTask *task, gpointer src, gpointer data, GCancellable *c)
{
  FpiDeviceFpc1540Ta *self = FPI_DEVICE_FPC1540TA (src);
  char reply[512];
  if (!ta_cmd (self, "open", reply, sizeof reply, 20000))
    { g_task_return_new_error (task, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                               "helper open timed out"); return; }
  if (!strstr (reply, "sensor=0"))
    { g_task_return_new_error (task, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                               "sensor init failed: %s", reply); return; }
  g_task_return_boolean (task, TRUE);
}
static void
open_done (GObject *src, GAsyncResult *res, gpointer u)
{
  GError *error = NULL;
  g_task_propagate_boolean (G_TASK (res), &error);
  fpi_device_open_complete (FP_DEVICE (src), error);
}
static void
dev_open (FpDevice *device)
{
  FpiDeviceFpc1540Ta *self = FPI_DEVICE_FPC1540TA (device);
  GError *error = NULL;
  GTask *task;
  self->fd = ta_connect (&error);
  if (self->fd < 0)
    { fpi_device_open_complete (device, error); return; }
  g_mkdir_with_parents (ta_dir (), 0700);
  task = g_task_new (device, NULL, open_done, NULL);
  g_task_run_in_thread (task, open_thread);
  g_object_unref (task);
}
static void
dev_close (FpDevice *device)
{
  FpiDeviceFpc1540Ta *self = FPI_DEVICE_FPC1540TA (device);
  if (self->fd >= 0)
    {
      char reply[64];
      ta_cmd (self, "quit", reply, sizeof reply, 1000);
      close (self->fd);
      self->fd = -1;
    }
  fpi_device_close_complete (device, NULL);
}

/* ------------------------------------------------------------------ */
/* enroll                                                              */
/* ------------------------------------------------------------------ */

static gboolean
enroll_progress_idle (gpointer data)
{
  int n = GPOINTER_TO_INT (data);
  if (g_self && g_self->enroll_print)
    fpi_device_enroll_progress (FP_DEVICE (g_self),
                                MIN (n, FPC1540TA_NR_STAGES - 1),
                                g_self->enroll_print, NULL);
  return G_SOURCE_REMOVE;
}

static void
enroll_thread (GTask *task, gpointer src, gpointer data, GCancellable *c)
{
  FpiDeviceFpc1540Ta *self = FPI_DEVICE_FPC1540TA (src);
  char reply[256];
  long status = -1;
  guint32 gid = ta_next_gid ();
  g_autofree gchar *set = ta_set_path (gid);
  g_autofree gchar *cmd = g_strdup_printf ("new_set %u", gid);

  if (!ta_cmd (self, cmd, reply, sizeof reply, 20000) || strncmp (reply, "ret=0", 5))
    { g_task_return_new_error (task, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                               "new_set: %s", reply); return; }
  if (!ta_write (self, "enroll_run"))
    { g_task_return_new_error (task, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                               "enroll_run write failed"); return; }
  while (ta_read_line (self->fd, reply, sizeof reply, 180000))
    {
      int n;
      if (sscanf (reply, "stage %d", &n) == 1)
        g_main_context_invoke (NULL, enroll_progress_idle, GINT_TO_POINTER (n));
      else if (sscanf (reply, "result %ld", &status) == 1)
        break;
    }
  if (status != 0)
    { g_task_return_new_error (task, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                               "enroll failed (%ld)", status); return; }
  cmd = g_strdup_printf ("save_set %s", set);
  ta_cmd (self, cmd, reply, sizeof reply, 30000);
  g_task_return_int (task, (gint) gid);
}

static void
enroll_done (GObject *src, GAsyncResult *res, gpointer u)
{
  FpiDeviceFpc1540Ta *self = FPI_DEVICE_FPC1540TA (src);
  GError *error = NULL;
  gint gid = g_task_propagate_int (G_TASK (res), &error);
  FpPrint *print = NULL;

  fpi_device_get_enroll_data (FP_DEVICE (self), &print);
  g_clear_object (&self->enroll_print);
  fpi_device_report_finger_status (FP_DEVICE (self), FP_FINGER_STATUS_NONE);
  if (error || !print)
    {
      fpi_device_enroll_complete (FP_DEVICE (self), NULL, error);
      return;
    }
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);
  g_object_set (print, "fpi-data", g_variant_new_uint32 (gid), NULL);
  fpi_device_enroll_progress (FP_DEVICE (self), FPC1540TA_NR_STAGES - 1, print, NULL);
  /* pass a fresh ref; the core owns the template via the enroll data */
  fpi_device_enroll_complete (FP_DEVICE (self), g_object_ref (print), NULL);
}

static void
dev_enroll (FpDevice *device)
{
  FpiDeviceFpc1540Ta *self = FPI_DEVICE_FPC1540TA (device);
  FpPrint *print = NULL;
  GTask *task;
  fpi_device_get_enroll_data (device, &print);
  self->enroll_print = g_object_ref (print);
  g_self = self;
  fpi_device_report_finger_status_changes (device, FP_FINGER_STATUS_NEEDED,
                                           FP_FINGER_STATUS_NONE);
  task = g_task_new (device, NULL, enroll_done, NULL);
  g_task_run_in_thread (task, enroll_thread);
  g_object_unref (task);
}

/* ------------------------------------------------------------------ */
/* identify / verify (one capture per set, done in the helper)         */
/* ------------------------------------------------------------------ */

static void
identify_thread (GTask *task, gpointer src, gpointer data, GCancellable *c)
{
  FpiDeviceFpc1540Ta *self = FPI_DEVICE_FPC1540TA (src);
  FpiDeviceAction action = fpi_device_get_current_action (FP_DEVICE (self));
  char reply[256];
  long status = -1;
  guint matched = 0, gid = 0, score = 0;

  self->out_matched = FALSE;
  self->out_gid = 0;
  self->out_score = 0;
  fp_dbg ("fpc1540ta identify_thread: action=%d target=%p", action, self->op_target);

  if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      /* Compare the presented finger against the *target* template only.
       * identify_sets searches every set, which is ambiguous when the same
       * finger was enrolled more than once: the first matching set in
       * directory order can be a different GID than the target, and the caller
       * then reports NO MATCH (seen as alternating MATCH/NO MATCH). */
      g_autoptr(GVariant) d = NULL;
      guint32 tgid = 0;
      g_autofree gchar *set = NULL;
      g_autofree gchar *cmd = NULL;

      if (self->op_target)
        g_object_get (self->op_target, "fpi-data", &d, NULL);
      if (d && g_variant_is_of_type (d, G_VARIANT_TYPE_UINT32))
        tgid = g_variant_get_uint32 (d);
      set = ta_set_path (tgid);
      fp_dbg ("fpc1540ta verify: target gid=%u set=%s", tgid, set);
      cmd = g_strdup_printf ("use_set %u %s", tgid, set);
      if (!ta_cmd (self, cmd, reply, sizeof reply, 30000) ||
          !ta_write (self, "identify_run"))
        { g_task_return_boolean (task, FALSE); return; }
      while (ta_read_line (self->fd, reply, sizeof reply, 180000))
        if (sscanf (reply, "result %ld %u %u %u", &status, &matched, &gid, &score) == 4)
          break;
      if (matched)
        gid = tgid;   /* the only set loaded, so a match is the target */
    }
  else
    {
      /* Identify: only test the prints the caller passed (fprintd passes the
       * user's prints).  Scanning every set-*.bin on disk matched unrelated old
       * templates, so an enrolled finger could be reported as no-match. */
      g_autoptr(GString) c = g_string_new ("identify_sets ");
      g_string_append (c, ta_dir ());
      for (guint i = 0; self->op_prints && i < self->op_prints->len; i++)
        {
          FpPrint *p = g_ptr_array_index (self->op_prints, i);
          g_autoptr(GVariant) d = NULL;
          g_object_get (p, "fpi-data", &d, NULL);
          if (d && g_variant_is_of_type (d, G_VARIANT_TYPE_UINT32))
            g_string_append_printf (c, " %u", g_variant_get_uint32 (d));
        }
      g_autofree gchar *cmd = g_string_free (g_steal_pointer (&c), FALSE);
      fp_dbg ("fpc1540ta identify: %s", cmd);
      if (!ta_write (self, cmd))
        { g_task_return_boolean (task, FALSE); return; }
      while (ta_read_line (self->fd, reply, sizeof reply, 180000))
        if (sscanf (reply, "result %ld %u %u %u", &status, &matched, &gid, &score) == 4)
          break;
    }

  self->out_matched = matched != 0;
  self->out_gid = gid;
  self->out_score = score;
  fp_dbg ("identify: status=%ld matched=%u gid=%u score=%u",
          status, matched, gid, score);
  g_task_return_boolean (task, TRUE);
}

static void
identify_done (GObject *src, GAsyncResult *res, gpointer u)
{
  FpiDeviceFpc1540Ta *self = FPI_DEVICE_FPC1540TA (src);
  FpDevice *device = FP_DEVICE (src);
  g_autoptr(GError) error = NULL;
  FpPrint *match = NULL;
  FpiDeviceAction action = fpi_device_get_current_action (device);

  g_task_propagate_boolean (G_TASK (res), &error);
  fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);

  if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      guint32 tgid = 0;
      g_autoptr(GVariant) data = NULL;
      if (self->op_target)
        {
          g_object_get (self->op_target, "fpi-data", &data, NULL);
          if (data && g_variant_is_of_type (data, G_VARIANT_TYPE_UINT32))
            tgid = g_variant_get_uint32 (data);
        }
      fpi_device_verify_report (device,
                                (!error && self->out_matched && self->out_gid == tgid)
                                ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                                self->op_target, NULL);
      g_clear_object (&self->op_target);
      fpi_device_verify_complete (device, NULL);
      return;
    }

  if (!error && self->out_matched && self->op_prints)
    {
      for (guint i = 0; i < self->op_prints->len && !match; i++)
        {
          FpPrint *p = g_ptr_array_index (self->op_prints, i);
          g_autoptr(GVariant) data = NULL;
          g_object_get (p, "fpi-data", &data, NULL);
          if (data && g_variant_is_of_type (data, G_VARIANT_TYPE_UINT32) &&
              g_variant_get_uint32 (data) == self->out_gid)
            match = p;
        }
    }
  g_clear_pointer (&self->op_prints, g_ptr_array_unref);
  fpi_device_identify_report (device, match, match, NULL);
  fpi_device_identify_complete (device, NULL);
}

static void
dev_verify_identify (FpDevice *device)
{
  FpiDeviceFpc1540Ta *self = FPI_DEVICE_FPC1540TA (device);
  FpiDeviceAction action = fpi_device_get_current_action (device);
  GTask *task;

  if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      FpPrint *target = NULL;
      fpi_device_get_verify_data (device, &target);
      self->op_target = g_object_ref (target);
    }
  else
    {
      GPtrArray *prints = NULL;
      fpi_device_get_identify_data (device, &prints);
      self->op_prints = g_ptr_array_ref (prints);
    }

  fpi_device_report_finger_status_changes (device, FP_FINGER_STATUS_NEEDED,
                                           FP_FINGER_STATUS_NONE);
  task = g_task_new (device, NULL, identify_done, NULL);
  g_task_run_in_thread (task, identify_thread);
  g_object_unref (task);
}

/* ------------------------------------------------------------------ */
/* list / delete / clear                                               */
/* ------------------------------------------------------------------ */

static void
list_thread (GTask *task, gpointer src, gpointer data, GCancellable *c)
{
  FpiDeviceFpc1540Ta *self = FPI_DEVICE_FPC1540TA (src);
  g_autoptr(GArray) gids = ta_scan_gids ();
  g_autoptr(GArray) result = g_array_new (FALSE, FALSE, sizeof (guint32));
  char reply[256];

  for (guint i = 0; i < gids->len; i++)
    {
      guint32 gid = g_array_index (gids, guint32, i);
      g_autofree gchar *set = ta_set_path (gid);
      g_autofree gchar *cmd = g_strdup_printf ("use_set %u %s", gid, set);
      guint count = 0;

      if (!ta_cmd (self, cmd, reply, sizeof reply, 30000))
        continue;
      if (!ta_write (self, "get_ids") ||
          !ta_read_line (self->fd, reply, sizeof reply, 10000))
        continue;
      sscanf (reply, "count %u", &count);
      while (ta_read_line (self->fd, reply, sizeof reply, 5000))
        if (g_str_has_prefix (reply, "end"))
          break;
      if (count > 0)
        g_array_append_val (result, gid);
    }
  g_task_return_pointer (task, g_steal_pointer (&result),
                         (GDestroyNotify) g_array_unref);
}

static void
list_done (GObject *src, GAsyncResult *res, gpointer u)
{
  FpDevice *device = FP_DEVICE (src);
  g_autoptr(GError) error = NULL;
  g_autoptr(GArray) gids = g_task_propagate_pointer (G_TASK (res), &error);
  g_autoptr(GPtrArray) prints = g_ptr_array_new_with_free_func (g_object_unref);

  if (error)
    { fpi_device_list_complete (device, NULL, g_steal_pointer (&error)); return; }
  for (guint i = 0; gids && i < gids->len; i++)
    {
      guint32 gid = g_array_index (gids, guint32, i);
      FpPrint *print = fp_print_new (device);
      fpi_print_set_type (print, FPI_PRINT_RAW);
      fpi_print_set_device_stored (print, TRUE);
      g_object_set (print, "fpi-data", g_variant_new_uint32 (gid), NULL);
      g_ptr_array_add (prints, print);
    }
  fpi_device_list_complete (device, g_steal_pointer (&prints), NULL);
}

static void
dev_list (FpDevice *device)
{
  GTask *task = g_task_new (device, NULL, list_done, NULL);
  g_task_run_in_thread (task, list_thread);
  g_object_unref (task);
}

static void
delete_thread (GTask *task, gpointer src, gpointer data, GCancellable *c)
{
  FpiDeviceFpc1540Ta *self = FPI_DEVICE_FPC1540TA (src);
  g_autofree gchar *set = ta_set_path (self->out_gid);
  g_autofree gchar *cmd = g_strdup_printf ("use_set %u %s", self->out_gid, set);
  char reply[256];
  guint count = 0;

  ta_cmd (self, cmd, reply, sizeof reply, 30000);
  if (ta_write (self, "get_ids") &&
      ta_read_line (self->fd, reply, sizeof reply, 10000))
    {
      sscanf (reply, "count %u", &count);
      for (guint i = 0; i < count && i < 16; i++)
        {
          guint32 id;
          if (!ta_read_line (self->fd, reply, sizeof reply, 5000))
            break;
          if (sscanf (reply, "id %u", &id) == 1)
            {
              g_autofree gchar *dc = g_strdup_printf ("delete %u", id);
              ta_cmd (self, dc, reply, sizeof reply, 20000);
            }
        }
      while (ta_read_line (self->fd, reply, sizeof reply, 2000))
        if (g_str_has_prefix (reply, "end"))
          break;
    }
  g_unlink (set);
  g_task_return_boolean (task, TRUE);
}

static void
delete_done (GObject *src, GAsyncResult *res, gpointer u)
{
  GError *error = NULL;
  g_task_propagate_boolean (G_TASK (res), &error);
  fpi_device_delete_complete (FP_DEVICE (src), error);
}

static void
dev_delete (FpDevice *device)
{
  FpiDeviceFpc1540Ta *self = FPI_DEVICE_FPC1540TA (device);
  FpPrint *print = NULL;
  g_autoptr(GVariant) data = NULL;
  GTask *task;

  fpi_device_get_delete_data (device, &print);
  g_object_get (print, "fpi-data", &data, NULL);
  self->out_gid = 0;
  if (data && g_variant_is_of_type (data, G_VARIANT_TYPE_UINT32))
    self->out_gid = g_variant_get_uint32 (data);
  task = g_task_new (device, NULL, delete_done, NULL);
  g_task_run_in_thread (task, delete_thread);
  g_object_unref (task);
}

static void
clear_thread (GTask *task, gpointer src, gpointer data, GCancellable *c)
{
  g_autoptr(GDir) dir = g_dir_open (ta_dir (), 0, NULL);
  const char *name;
  while (dir && (name = g_dir_read_name (dir)))
    {
      guint32 gid;
      if (sscanf (name, "set-%u.bin", &gid) == 1)
        {
          g_autofree gchar *p = g_build_filename (ta_dir (), name, NULL);
          g_unlink (p);
        }
    }
  g_task_return_boolean (task, TRUE);
}

static void
clear_done (GObject *src, GAsyncResult *res, gpointer u)
{
  GError *error = NULL;
  g_task_propagate_boolean (G_TASK (res), &error);
  fpi_device_clear_storage_complete (FP_DEVICE (src), error);
}

static void
dev_clear_storage (FpDevice *device)
{
  GTask *task = g_task_new (device, NULL, clear_done, NULL);
  g_task_run_in_thread (task, clear_thread);
  g_object_unref (task);
}

/* ------------------------------------------------------------------ */
/* Boilerplate                                                         */
/* ------------------------------------------------------------------ */

static const FpIdEntry id_table[] = {
  { .virtual_envvar = "FP_FPC1540TA" },
  { .virtual_envvar = NULL },
};

static void
fpi_device_fpc1540ta_init (FpiDeviceFpc1540Ta *self)
{
  self->fd = -1;
  g_mutex_init (&self->lock);
}

static void
fpi_device_fpc1540ta_finalize (GObject *object)
{
  FpiDeviceFpc1540Ta *self = FPI_DEVICE_FPC1540TA (object);
  if (self->fd >= 0) { close (self->fd); self->fd = -1; }
  g_clear_object (&self->enroll_print);
  g_clear_object (&self->op_target);
  g_clear_pointer (&self->op_prints, g_ptr_array_unref);
  g_mutex_clear (&self->lock);
  G_OBJECT_CLASS (fpi_device_fpc1540ta_parent_class)->finalize (object);
}

static void
fpi_device_fpc1540ta_class_init (FpiDeviceFpc1540TaClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = fpi_device_fpc1540ta_finalize;
  dev_class->id = "fpc1540ta";
  dev_class->full_name = "FPC1540 match-on-chip (stock TA, userspace)";
  dev_class->type = FP_DEVICE_TYPE_VIRTUAL;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = FPC1540TA_NR_STAGES;
  dev_class->temp_hot_seconds = -1;
  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify_identify;
  dev_class->identify = dev_verify_identify;
  dev_class->list = dev_list;
  dev_class->delete = dev_delete;
  dev_class->clear_storage = dev_clear_storage;
  dev_class->features |= FP_DEVICE_FEATURE_STORAGE |
                         FP_DEVICE_FEATURE_STORAGE_LIST |
                         FP_DEVICE_FEATURE_STORAGE_DELETE |
                         FP_DEVICE_FEATURE_STORAGE_CLEAR;
  fpi_device_class_auto_initialize_features (dev_class);
}
