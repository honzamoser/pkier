package db

import (
"time"
)

type DashboardMetrics struct {
DBSize        int64
RecentCerts   []CertRecord
ExpiringCerts []CertRecord
}

func GetDashboardMetrics() DashboardMetrics {
var m DashboardMetrics

err := Db.QueryRow("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()").Scan(&m.DBSize)
if err != nil {
m.DBSize = 0
}

rows, err := Db.Query("SELECT serial_number, subject, status, expiry_date FROM certificates ORDER BY issue_date DESC LIMIT 5")
if err == nil {
defer rows.Close()
for rows.Next() {
var c CertRecord
var exp string
rows.Scan(&c.Serial, &c.Subject, &c.Status, &exp)
c.Expiry = exp
m.RecentCerts = append(m.RecentCerts, c)
}
}

now := time.Now()
thirtyDays := now.AddDate(0, 0, 30)

allValid, err := GetValidCertificates()
if err == nil {
for _, cert := range allValid {
// Ca.go format: 2006-01-02 15:04
parsedTime, parseErr := time.Parse("2006-01-02 15:04", cert.Expiry)
if parseErr == nil && parsedTime.Before(thirtyDays) && parsedTime.After(now) {
m.ExpiringCerts = append(m.ExpiringCerts, cert)
}
if len(m.ExpiringCerts) >= 5 {
break
}
}
}

return m
}
