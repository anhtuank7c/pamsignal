#ifndef JOURNAL_WATCH_H
#define JOURNAL_WATCH_H

#include <systemd/sd-journal.h>

// Initialize journal: open, seek to tail, add filters
int ps_journal_watch_init(sd_journal **j);

// Run the event loop until 'running' becomes false
int ps_journal_watch_run(sd_journal *j);

// Close the journal
void ps_journal_watch_cleanup(sd_journal *j);

#endif /* JOURNAL_WATCH_H */
