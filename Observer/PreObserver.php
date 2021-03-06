<?php

namespace Pommes\Security\Observer;

use Magento\Framework\Event\ObserverInterface;

class PreObserver implements ObserverInterface {

    /**
     * Helper
     *
     * @var \Pommes\Security\Helper\Data
     */
    protected $_helper;

    /**
     * @\Pommes\Security\Helper\Data $helper
     */
    public function __construct(
        \Pommes\Security\Helper\Data $helper
    ) {
        $this->_helper = $helper;
    }

    /**
     * @param \Magento\Framework\Event\Observer $observer
     *
     * @return self
     */
    public function execute(\Magento\Framework\Event\Observer $observer) {

        if($this->_helper->isEnabled()) {

            /* Fetch stored protection list for current store */
            $protection_list = $this->_helper->getProtectionListAsArray();

            /* Get request */
            $controller_action = $observer->getEvent()->getControllerAction();
            $request = $controller_action->getRequest();
            if($request) {

                /* Get action name */
                $action_name = sprintf('%s_%s_%s',
                    $request->getModuleName(),
                    $request->getControllerName(),
                    $request->getActionName()
                );

                /* Check for entry in list */
                if(isset($protection_list[$action_name])) {

                    /* Do we have a lock? */
                    if($this->_helper->isLocked($request->getClientIp(), $action_name)) {

                        /* Die here and do nothing */
                        exit(0);
                    }
                }
            }
        }

        return $this;
    }
}
