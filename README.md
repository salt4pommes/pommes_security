# Pommes_Secure

Simple anti spam module for Magento 2.

You can define a maximum amount of calls for a specific action within a given time.
If maximum was reached, the action is blocked for specified amount of time.

## Requirements

- Magento 2
- Redis

## Setup

### Via Composer

Run at Magento root folder:

```bash
composer require pommes/security
bin/magento module:enable Pommes_Security
bin/magento setup:upgrade
```

### Manually

Create directory app/code/Pommes/Security and copy the all the files into it.

Then run:

```bash
bin/magento module:enable Pommes_Security
bin/magento setup:upgrade
```
