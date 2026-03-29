#ifndef JOURNAL_WATCH_H
#define JOURNAL_WATCH_H

#include <systemd/sd-journal.h>

// Initialize journal: open, seek to tail, add filters
int ps_journal_watch_init(sd_journal **j);

// Allocate the failed-login tracking table
int ps_fail_table_init(int capacity);

// Reset the failed-login tracking table (used on config reload)
void ps_fail_table_reset(void);

// Run the event loop until 'running' becomes false
int ps_journal_watch_run(sd_journal *j);

// Close the journal and free the fail table
void ps_journal_watch_cleanup(sd_journal *j);

#endif /* JOURNAL_WATCH_H */
