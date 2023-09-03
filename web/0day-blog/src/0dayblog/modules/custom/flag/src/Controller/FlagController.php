<?php
namespace Drupal\flag\Controller;
use Drupal\Core\Controller\ControllerBase;

class FlagController extends ControllerBase
{
    public function index()
    {
        return array(
            '#type' => 'markup',
            '#markup' => $this->t('Flag: DUCTF{c4cH3_m1_0uT51D3_w1Th_wHy_t0_n1T_c4Ch3_eHvrRiIet1nG!!1}!'),);
    }
}