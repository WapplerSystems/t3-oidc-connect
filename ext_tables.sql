CREATE TABLE fe_users (
	tx_oidcconnect_issuer varchar(255) DEFAULT '' NOT NULL,
	tx_oidcconnect_subject varchar(255) DEFAULT '' NOT NULL,

	KEY tx_oidcconnect_identity (tx_oidcconnect_subject(100), tx_oidcconnect_issuer(100))
);

CREATE TABLE be_users (
	tx_oidcconnect_issuer varchar(255) DEFAULT '' NOT NULL,
	tx_oidcconnect_subject varchar(255) DEFAULT '' NOT NULL,

	KEY tx_oidcconnect_identity (tx_oidcconnect_subject(100), tx_oidcconnect_issuer(100))
);

#
# One row per TYPO3 session that was created by an OIDC login. Used for
# RP-initiated logout (id_token_hint) and back-channel logout (sid/sub).
#
CREATE TABLE tx_oidcconnect_session (
	uid int(11) unsigned NOT NULL auto_increment,
	login_type varchar(2) DEFAULT '' NOT NULL,
	site varchar(255) DEFAULT '' NOT NULL,
	user_uid int(11) unsigned DEFAULT '0' NOT NULL,
	issuer varchar(255) DEFAULT '' NOT NULL,
	subject varchar(255) DEFAULT '' NOT NULL,
	sid varchar(255) DEFAULT '' NOT NULL,
	id_token text,
	crdate int(11) unsigned DEFAULT '0' NOT NULL,
	revoked int(11) unsigned DEFAULT '0' NOT NULL,

	PRIMARY KEY (uid),
	KEY sid (sid(100)),
	KEY subject (subject(100)),
	KEY crdate (crdate)
);
