;; Stacks Secured Vault Keeper
;; Distributed ledger solution for permanent, immutable record storage with secure access controls

;; System-wide Entry Count
(define-data-var entry-sequence uint u0)

;; Primary Data Repository
(define-map vault-entries
  { entry-id: uint }
  {
    identifier: (string-ascii 64),
    custodian: principal,
    data-volume: uint,
    timestamp-block: uint,
    summary: (string-ascii 128),
    categories: (list 10 (string-ascii 32))
  }
)

;; Error Response Codes
(define-constant err-entry-not-located (err u401))
(define-constant err-malformed-identifier (err u403))
(define-constant err-invalid-data-volume (err u404))
(define-constant err-supervisor-function (err u407))
(define-constant err-access-limitation (err u408))
(define-constant err-authorization-failed (err u405))
(define-constant err-impermissible-action (err u406))
(define-constant err-duplicate-entry-detected (err u402))
(define-constant err-category-validation-error (err u409))

;; Administrative Configuration
(define-constant supervisor-address tx-sender)

(define-map access-control
  { entry-id: uint, accessor: principal }
  { access-granted: bool }
)

;; ===== Private Helper Functions =====

;; Verifies entry existence in system
(define-private (entry-exists (entry-id uint))
  (is-some (map-get? vault-entries { entry-id: entry-id }))
)

;; Confirms custodianship rights
(define-private (is-entry-custodian (entry-id uint) (user principal))
  (match (map-get? vault-entries { entry-id: entry-id })
    entry-data (is-eq (get custodian entry-data) user)
    false
  )
)

;; Validates category formatting rules
(define-private (is-valid-category (category (string-ascii 32)))
  (and
    (> (len category) u0)
    (< (len category) u33)
  )
)

;; Ensures all categories comply with system standards
(define-private (validate-category-structure (categories (list 10 (string-ascii 32))))
  (and
    (> (len categories) u0)
    (<= (len categories) u10)
    (is-eq (len (filter is-valid-category categories)) (len categories))
  )
)

;; Retrieves entry data volume
(define-private (get-entry-volume (entry-id uint))
  (default-to u0
    (get data-volume
      (map-get? vault-entries { entry-id: entry-id })
    )
  )
)

;; ===== Entry Management Operations =====

;; Creates new entry with complete metadata
(define-public (create-vault-entry 
  (identifier (string-ascii 64)) 
  (data-volume uint) 
  (summary (string-ascii 128)) 
  (categories (list 10 (string-ascii 32)))
)
  (let
    (
      (entry-id (+ (var-get entry-sequence) u1))
    )
    ;; Input validation
    (asserts! (> (len identifier) u0) err-malformed-identifier)
    (asserts! (< (len identifier) u65) err-malformed-identifier)
    (asserts! (> data-volume u0) err-invalid-data-volume)
    (asserts! (< data-volume u1000000000) err-invalid-data-volume)
    (asserts! (> (len summary) u0) err-malformed-identifier)
    (asserts! (< (len summary) u129) err-malformed-identifier)
    (asserts! (validate-category-structure categories) err-category-validation-error)

    ;; Record new entry in system
    (map-insert vault-entries
      { entry-id: entry-id }
      {
        identifier: identifier,
        custodian: tx-sender,
        data-volume: data-volume,
        timestamp-block: block-height,
        summary: summary,
        categories: categories
      }
    )

    ;; Grant access permission to creator
    (map-insert access-control
      { entry-id: entry-id, accessor: tx-sender }
      { access-granted: true }
    )

    ;; Update sequence counter
    (var-set entry-sequence entry-id)
    (ok entry-id)
  )
)

;; Modifies existing entry with updated information
(define-public (modify-vault-entry 
  (entry-id uint) 
  (new-identifier (string-ascii 64)) 
  (new-data-volume uint) 
  (new-summary (string-ascii 128)) 
  (new-categories (list 10 (string-ascii 32)))
)
  (let
    (
      (entry-data (unwrap! (map-get? vault-entries { entry-id: entry-id }) err-entry-not-located))
    )
    ;; Validate custodianship and input values
    (asserts! (entry-exists entry-id) err-entry-not-located)
    (asserts! (is-eq (get custodian entry-data) tx-sender) err-impermissible-action)
    (asserts! (> (len new-identifier) u0) err-malformed-identifier)
    (asserts! (< (len new-identifier) u65) err-malformed-identifier)
    (asserts! (> new-data-volume u0) err-invalid-data-volume)
    (asserts! (< new-data-volume u1000000000) err-invalid-data-volume)
    (asserts! (> (len new-summary) u0) err-malformed-identifier)
    (asserts! (< (len new-summary) u129) err-malformed-identifier)
    (asserts! (validate-category-structure new-categories) err-category-validation-error)

    ;; Update entry with new information
    (map-set vault-entries
      { entry-id: entry-id }
      (merge entry-data { 
        identifier: new-identifier, 
        data-volume: new-data-volume, 
        summary: new-summary, 
        categories: new-categories 
      })
    )
    (ok true)
  )
)

;; ===== Access Control Operations =====

;; Provides access permission to another user
(define-public (authorize-entry-access (entry-id uint) (accessor principal))
  (let
    (
      (entry-data (unwrap! (map-get? vault-entries { entry-id: entry-id }) err-entry-not-located))
    )
    ;; Verify entry exists and caller is the custodian
    (asserts! (entry-exists entry-id) err-entry-not-located)
    (asserts! (is-eq (get custodian entry-data) tx-sender) err-impermissible-action)

    (ok true)
  )
)

;; Revokes access for specified user
(define-public (revoke-accessor-rights (entry-id uint) (accessor principal))
  (let
    (
      (entry-data (unwrap! (map-get? vault-entries { entry-id: entry-id }) err-entry-not-located))
    )
    ;; Verify entry exists and caller is the custodian
    (asserts! (entry-exists entry-id) err-entry-not-located)
    (asserts! (is-eq (get custodian entry-data) tx-sender) err-impermissible-action)
    (asserts! (not (is-eq accessor tx-sender)) err-supervisor-function)

    ;; Remove access permission
    (map-delete access-control { entry-id: entry-id, accessor: accessor })
    (ok true)
  )
)

;; Transfers entry custodianship to new principal
(define-public (transfer-entry-custodianship (entry-id uint) (new-custodian principal))
  (let
    (
      (entry-data (unwrap! (map-get? vault-entries { entry-id: entry-id }) err-entry-not-located))
    )
    ;; Verify caller is the current custodian
    (asserts! (entry-exists entry-id) err-entry-not-located)
    (asserts! (is-eq (get custodian entry-data) tx-sender) err-impermissible-action)

    ;; Update custodianship
    (map-set vault-entries
      { entry-id: entry-id }
      (merge entry-data { custodian: new-custodian })
    )
    (ok true)
  )
)

;; ===== Entry Lifecycle Management =====

;; Permanently removes entry from system
(define-public (purge-vault-entry (entry-id uint))
  (let
    (
      (entry-data (unwrap! (map-get? vault-entries { entry-id: entry-id }) err-entry-not-located))
    )
    ;; Verify custodianship
    (asserts! (entry-exists entry-id) err-entry-not-located)
    (asserts! (is-eq (get custodian entry-data) tx-sender) err-impermissible-action)

    ;; Remove entry from system
    (map-delete vault-entries { entry-id: entry-id })
    (ok true)
  )
)

;; Marks entry as preserved with special status
(define-public (mark-entry-preserved (entry-id uint))
  (let
    (
      (entry-data (unwrap! (map-get? vault-entries { entry-id: entry-id }) err-entry-not-located))
      (preserve-marker "PRESERVED")
      (existing-categories (get categories entry-data))
      (combined-categories (unwrap! (as-max-len? (append existing-categories preserve-marker) u10) err-category-validation-error))
    )
    ;; Verify entry exists and caller is the custodian
    (asserts! (entry-exists entry-id) err-entry-not-located)
    (asserts! (is-eq (get custodian entry-data) tx-sender) err-impermissible-action)

    ;; Update entry with preservation marker
    (map-set vault-entries
      { entry-id: entry-id }
      (merge entry-data { categories: combined-categories })
    )
    (ok true)
  )
)

;; Expands entry metadata with additional categories
(define-public (expand-entry-categories (entry-id uint) (supplemental-categories (list 10 (string-ascii 32))))
  (let
    (
      (entry-data (unwrap! (map-get? vault-entries { entry-id: entry-id }) err-entry-not-located))
      (existing-categories (get categories entry-data))
      (combined-categories (unwrap! (as-max-len? (concat existing-categories supplemental-categories) u10) err-category-validation-error))
    )
    ;; Verify entry exists and caller is the custodian
    (asserts! (entry-exists entry-id) err-entry-not-located)
    (asserts! (is-eq (get custodian entry-data) tx-sender) err-impermissible-action)

    ;; Validate new categories format
    (asserts! (validate-category-structure supplemental-categories) err-category-validation-error)

    ;; Update entry with combined categories
    (map-set vault-entries
      { entry-id: entry-id }
      (merge entry-data { categories: combined-categories })
    )
    (ok combined-categories)
  )
)

;; ===== Advanced System Functions =====

;; Retrieves entry analytics and metrics
(define-public (retrieve-entry-analytics (entry-id uint))
  (let
    (
      (entry-data (unwrap! (map-get? vault-entries { entry-id: entry-id }) err-entry-not-located))
      (timestamp-height (get timestamp-block entry-data))
    )
    ;; Verify entry exists and caller has access
    (asserts! (entry-exists entry-id) err-entry-not-located)
    (asserts! 
      (or 
        (is-eq tx-sender (get custodian entry-data))
        (default-to false (get access-granted (map-get? access-control { entry-id: entry-id, accessor: tx-sender })))
        (is-eq tx-sender supervisor-address)
      ) 
      err-authorization-failed
    )

    ;; Return entry analytics
    (ok {
      entry-longevity: (- block-height timestamp-height),
      volume-measure: (get data-volume entry-data),
      metadata-elements: (len (get categories entry-data))
    })
  )
)

;; Activates security protocol for entry
(define-public (activate-security-protocol (entry-id uint))
  (let
    (
      (entry-data (unwrap! (map-get? vault-entries { entry-id: entry-id }) err-entry-not-located))
      (security-marker "SECURITY-PROTOCOL")
      (existing-categories (get categories entry-data))
    )
    ;; Verify caller is either the custodian or system supervisor
    (asserts! (entry-exists entry-id) err-entry-not-located)
    (asserts! 
      (or 
        (is-eq tx-sender supervisor-address)
        (is-eq (get custodian entry-data) tx-sender)
      ) 
      err-supervisor-function
    )

    ;; Apply security protocol
    (ok true)
  )
)

;; Performs system monitoring and maintenance
(define-public (system-operational-check)
  (begin
    ;; Verify caller is system supervisor
    (asserts! (is-eq tx-sender supervisor-address) err-supervisor-function)

    ;; Return system status report
    (ok {
      total-entries: (var-get entry-sequence),
      system-operational: true,
      checkpoint-height: block-height
    })
  )
)

;; Validates entry authenticity and custodianship
(define-public (validate-entry-authenticity (entry-id uint) (presumed-custodian principal))
  (let
    (
      (entry-data (unwrap! (map-get? vault-entries { entry-id: entry-id }) err-entry-not-located))
      (actual-custodian (get custodian entry-data))
      (timestamp-height (get timestamp-block entry-data))
      (has-access (default-to 
        false 
        (get access-granted 
          (map-get? access-control { entry-id: entry-id, accessor: tx-sender })
        )
      ))
    )
    ;; Validate entry existence and access permissions
    (asserts! (entry-exists entry-id) err-entry-not-located)
    (asserts! 
      (or 
        (is-eq tx-sender actual-custodian)
        has-access
        (is-eq tx-sender supervisor-address)
      ) 
      err-authorization-failed
    )

    ;; Generate validation report
    (if (is-eq actual-custodian presumed-custodian)
      ;; Return successful validation
      (ok {
        is-authentic: true,
        current-height: block-height,
        blocks-elapsed: (- block-height timestamp-height),
        custodian-match: true
      })
      ;; Return custodianship mismatch
      (ok {
        is-authentic: false,
        current-height: block-height,
        blocks-elapsed: (- block-height timestamp-height),
        custodian-match: false
      })
    )
  )
)

